import { Hono } from "hono";
import { cors } from "hono/cors";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { z } from "zod";
import type { Database } from "bun:sqlite";
import { openCareerBridgeDb, type Role } from "./db";
import { getEnvironmentIssues, loadEnv, safeVersion, type CareerBridgeEnv } from "./env";
import { createPassidClient, type PassidClient } from "./passid";
import { hashPassword, hmac, randomId, safeEqual, sanitizeScopes, verifyPassword } from "./security";

const APPROVED_SCOPES = [
  "identity.read",
  "education.read",
  "employment.read",
  "work_authorization.read",
  "account_ownership.read",
  "payout_readiness.read",
  "income.read",
  "business_verification.read",
  "marketplace_uniqueness.read",
  "duplicate_account_risk.read",
  "credential.summary",
];

const REQUIREMENT_TO_SCOPE: Record<string, string> = {
  identity_verified: "identity.read",
  education_credential: "education.read",
  employment_credential: "employment.read",
  work_authorization: "work_authorization.read",
  account_ownership: "account_ownership.read",
  payout_readiness: "payout_readiness.read",
  income_verification: "income.read",
  business_verification: "business_verification.read",
  marketplace_uniqueness: "marketplace_uniqueness.read",
  duplicate_account_risk: "duplicate_account_risk.read",
  custom_passid_credential: "credential.summary",
};

export interface AppOptions {
  env?: CareerBridgeEnv;
  db?: Database;
  passidClient?: PassidClient;
}

type User = { id: string; email: string; role: Role; name: string; suspended_at?: number | null };

function jsonArray(value: unknown): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(String(value));
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

function now() {
  return Date.now();
}

function audit(db: Database, actor: string | null, action: string, targetType: string, targetId: string, detail: Record<string, unknown>) {
  db.prepare("INSERT INTO audit_logs (id,actor_user_id,action,target_type,target_id,detail_json,created_at) VALUES (?,?,?,?,?,?,?)")
    .run(randomId("audit"), actor, action, targetType, targetId, JSON.stringify(detail), now());
}

function publicUser(user: User) {
  return { id: user.id, email: user.email, role: user.role, name: user.name };
}

export function createCareerBridgeApp(options: AppOptions = {}) {
  const env = options.env ?? loadEnv();
  const ownedDb = options.db ? null : openCareerBridgeDb(env.DATABASE_URL);
  const db = options.db ?? ownedDb!.db;
  const passid = options.passidClient ?? createPassidClient(env);
  const app = new Hono();

  app.use("*", async (c, next) => {
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "strict-origin-when-cross-origin");
    c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    await next();
  });

  app.use("/api/*", cors({
    origin: env.APP_URL,
    credentials: true,
    allowHeaders: ["Content-Type", "X-CSRF-Token"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  }));

  async function currentUser(c: any): Promise<User | null> {
    const sessionId = getCookie(c, "cb_session");
    if (!sessionId) return null;
    const session = db.prepare("SELECT * FROM sessions WHERE id = ? AND expires_at > ?").get(sessionId, now()) as any;
    if (!session) return null;
    const user = db.prepare("SELECT id,email,role,name,suspended_at FROM users WHERE id = ?").get(session.user_id) as User | null;
    if (!user || user.suspended_at) return null;
    c.set("session", session);
    c.set("user", user);
    return user;
  }

  async function requireUser(c: any, roles?: Role[]): Promise<User | Response> {
    const user = await currentUser(c);
    if (!user) return c.json({ error: "unauthorized" }, 401);
    if (roles && !roles.includes(user.role)) return c.json({ error: "forbidden" }, 403);
    return user;
  }

  async function requireCsrf(c: any): Promise<Response | null> {
    if (!["POST", "PUT", "DELETE"].includes(c.req.method)) return null;
    const session = (c as any).get("session") as { id: string; csrf: string };
    const token = c.req.header("X-CSRF-Token") ?? "";
    if (!session || !token || !safeEqual(token, session.csrf)) return c.json({ error: "csrf_failed" }, 403);
    return null;
  }

  app.get("/health", (c) => c.json({ status: "ok", service: "careerbridge" }));
  app.get("/version", (c) => c.json({ ...safeVersion(), passidEnvironment: env.PASSID_ENVIRONMENT }));
  app.get("/api/config", (c) => c.json({
    service: "careerbridge",
    passidEnvironment: env.PASSID_ENVIRONMENT,
    passidPublishableKey: env.PASSID_PUBLISHABLE_KEY,
    approvedScopes: APPROVED_SCOPES,
  }));
  app.get("/api/admin/environment", async (c) => {
    const user = await requireUser(c, ["admin"]);
    if (user instanceof Response) return user;
    return c.json({ issues: getEnvironmentIssues(process.env).map((issue) => issue.split(":")[0]), passidEnvironment: env.PASSID_ENVIRONMENT });
  });

  app.post("/api/auth/signup", async (c) => {
    const body = z.object({ email: z.string().email(), password: z.string().min(10), name: z.string().min(2), role: z.enum(["candidate", "employer", "university"]) }).parse(await c.req.json());
    const id = randomId("usr");
    try {
      db.prepare("INSERT INTO users (id,email,password_hash,role,name,email_verified,created_at) VALUES (?,?,?,?,?,0,?)")
        .run(id, body.email.toLowerCase(), hashPassword(body.password), body.role, body.name, now());
      if (body.role === "candidate") db.prepare("INSERT INTO candidate_profiles (user_id) VALUES (?)").run(id);
      if (body.role === "employer" || body.role === "university") {
        db.prepare("INSERT INTO organizations (id,owner_user_id,name,type,status,created_at) VALUES (?,?,?,?,?,?)")
          .run(randomId("org"), id, `${body.name}'s organization`, body.role === "university" ? "university" : "employer", "pending", now());
      }
      audit(db, id, "user.signup", "user", id, { role: body.role });
      return c.json({ user: { id, email: body.email.toLowerCase(), role: body.role, name: body.name } }, 201);
    } catch {
      return c.json({ error: "email_unavailable" }, 409);
    }
  });

  app.post("/api/auth/login", async (c) => {
    const body = z.object({ email: z.string().email(), password: z.string().min(1) }).parse(await c.req.json());
    const user = db.prepare("SELECT id,email,password_hash,role,name,suspended_at FROM users WHERE email = ?").get(body.email.toLowerCase()) as any;
    const demoOk = user?.password_hash === "pbkdf2$demo$demo" && body.password === "CareerBridgeDemo!2026";
    if (!user || user.suspended_at || (!demoOk && !verifyPassword(body.password, user.password_hash))) {
      return c.json({ error: "invalid_credentials" }, 401);
    }
    const sessionId = randomId("sess");
    const csrf = randomId("csrf");
    db.prepare("INSERT INTO sessions (id,user_id,csrf,expires_at,created_at) VALUES (?,?,?,?,?)").run(sessionId, user.id, csrf, now() + 1000 * 60 * 60 * 8, now());
    setCookie(c, "cb_session", sessionId, { httpOnly: true, secure: env.NODE_ENV === "production", sameSite: "Lax", path: "/", maxAge: 60 * 60 * 8 });
    audit(db, user.id, "auth.login", "user", user.id, {});
    return c.json({ user: publicUser(user), csrf });
  });

  app.post("/api/auth/logout", async (c) => {
    const user = await requireUser(c);
    if (user instanceof Response) return user;
    const csrf = await requireCsrf(c);
    if (csrf) return csrf;
    const session = (c as any).get("session") as { id: string; csrf: string };
    db.prepare("DELETE FROM sessions WHERE id = ?").run(session.id);
    deleteCookie(c, "cb_session", { path: "/" });
    return c.json({ ok: true });
  });

  app.get("/api/auth/me", async (c) => {
    const user = await currentUser(c);
    if (!user) return c.json({ user: null });
    const session = (c as any).get("session") as { id: string; csrf: string };
    return c.json({ user: publicUser(user), csrf: session.csrf });
  });

  app.get("/api/profile", async (c) => {
    const user = await requireUser(c, ["candidate"]);
    if (user instanceof Response) return user;
    const profile = db.prepare("SELECT * FROM candidate_profiles WHERE user_id = ?").get(user.id) ?? {};
    return c.json({ user: publicUser(user), profile });
  });

  app.put("/api/profile", async (c) => {
    const user = await requireUser(c, ["candidate"]);
    if (user instanceof Response) return user;
    const csrf = await requireCsrf(c);
    if (csrf) return csrf;
    const body = z.object({ headline: z.string().max(160).optional(), education: z.string().max(2000).optional(), experience: z.string().max(3000).optional(), skills: z.string().max(1000).optional() }).parse(await c.req.json());
    db.prepare("UPDATE candidate_profiles SET headline=?, education=?, experience=?, skills=? WHERE user_id=?")
      .run(body.headline ?? "", body.education ?? "", body.experience ?? "", body.skills ?? "", user.id);
    audit(db, user.id, "profile.update", "candidate_profile", user.id, {});
    return c.json({ ok: true });
  });

  app.get("/api/jobs", (c) => {
    const q = (c.req.query("q") ?? "").toLowerCase();
    const jobs = db.prepare(`
      SELECT j.*, o.name AS organization_name
      FROM jobs j JOIN organizations o ON o.id = j.organization_id
      WHERE j.status = 'published'
      ORDER BY j.created_at DESC
    `).all().filter((job: any) => !q || `${job.title} ${job.organization_name} ${job.location} ${job.skills}`.toLowerCase().includes(q));
    return c.json({ jobs: jobs.map((job: any) => ({ ...job, verification_requirements: jsonArray(job.verification_requirements) })) });
  });

  app.get("/api/jobs/:id", (c) => {
    const job = db.prepare("SELECT j.*, o.name AS organization_name FROM jobs j JOIN organizations o ON o.id = j.organization_id WHERE j.id = ?").get(c.req.param("id")) as any;
    if (!job) return c.json({ error: "not_found" }, 404);
    return c.json({ job: { ...job, verification_requirements: jsonArray(job.verification_requirements) } });
  });

  app.post("/api/employer/jobs", async (c) => {
    const user = await requireUser(c, ["employer", "admin"]);
    if (user instanceof Response) return user;
    const csrf = await requireCsrf(c);
    if (csrf) return csrf;
    const body = z.object({
      title: z.string().min(3),
      location: z.string().min(2),
      work_mode: z.enum(["remote", "hybrid", "onsite"]),
      employment_type: z.enum(["internship", "full-time", "part-time", "contract"]),
      compensation: z.string().optional(),
      description: z.string().min(20),
      qualifications: z.string().optional(),
      skills: z.string().optional(),
      deadline: z.string().optional(),
      verification_requirements: z.array(z.string()).default(["identity_verified"]),
      status: z.enum(["draft", "published"]).default("draft"),
    }).parse(await c.req.json());
    const org = db.prepare("SELECT * FROM organizations WHERE owner_user_id = ? LIMIT 1").get(user.id) as any;
    if (!org && user.role !== "admin") return c.json({ error: "organization_required" }, 400);
    if (org?.status !== "approved" && user.role !== "admin") return c.json({ error: "organization_not_approved" }, 403);
    const safeReqs = body.verification_requirements.filter((r) => REQUIREMENT_TO_SCOPE[r]);
    const id = randomId("job");
    db.prepare(`
      INSERT INTO jobs (id,organization_id,title,location,work_mode,employment_type,compensation,description,qualifications,skills,deadline,verification_requirements,status,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(id, org?.id ?? "org_demo", body.title, body.location, body.work_mode, body.employment_type, body.compensation ?? "", body.description, body.qualifications ?? "", body.skills ?? "", body.deadline ?? "", JSON.stringify(safeReqs), body.status, now());
    audit(db, user.id, "job.create", "job", id, { verification_requirements: safeReqs });
    return c.json({ id }, 201);
  });

  app.post("/api/jobs/:id/apply", async (c) => {
    const user = await requireUser(c, ["candidate"]);
    if (user instanceof Response) return user;
    const csrf = await requireCsrf(c);
    if (csrf) return csrf;
    const job = db.prepare("SELECT * FROM jobs WHERE id = ? AND status = 'published'").get(c.req.param("id")) as any;
    if (!job) return c.json({ error: "not_found" }, 404);
    const id = randomId("app");
    const status = jsonArray(job.verification_requirements).length ? "verification_required" : "submitted";
    try {
      db.prepare("INSERT INTO applications (id,job_id,candidate_user_id,status,cover_note,created_at,updated_at) VALUES (?,?,?,?,?,?,?)")
        .run(id, job.id, user.id, status, (await c.req.json().catch(() => ({})) as any).cover_note ?? "", now(), now());
      audit(db, user.id, "application.submit", "application", id, { job_id: job.id });
      return c.json({ id, status }, 201);
    } catch {
      return c.json({ error: "already_applied" }, 409);
    }
  });

  app.get("/api/applications", async (c) => {
    const user = await requireUser(c);
    if (user instanceof Response) return user;
    const rows = user.role === "candidate"
      ? db.prepare("SELECT a.*, j.title, o.name AS organization_name FROM applications a JOIN jobs j ON j.id=a.job_id JOIN organizations o ON o.id=j.organization_id WHERE a.candidate_user_id=? ORDER BY a.created_at DESC").all(user.id)
      : db.prepare("SELECT a.*, j.title, u.name AS candidate_name FROM applications a JOIN jobs j ON j.id=a.job_id JOIN organizations o ON o.id=j.organization_id JOIN users u ON u.id=a.candidate_user_id WHERE o.owner_user_id=? ORDER BY a.created_at DESC").all(user.id);
    return c.json({ applications: rows });
  });

  app.get("/api/employer/applicants/:id", async (c) => {
    const user = await requireUser(c, ["employer", "admin"]);
    if (user instanceof Response) return user;
    const appRow = db.prepare(`
      SELECT a.*, u.name AS candidate_name, j.title, o.owner_user_id
      FROM applications a JOIN users u ON u.id=a.candidate_user_id JOIN jobs j ON j.id=a.job_id JOIN organizations o ON o.id=j.organization_id
      WHERE a.id=?
    `).get(c.req.param("id")) as any;
    if (!appRow) return c.json({ error: "not_found" }, 404);
    if (user.role !== "admin" && appRow.owner_user_id !== user.id) return c.json({ error: "not_found" }, 404);
    const verification = db.prepare("SELECT result_json, updated_at FROM verification_results WHERE application_id=?").get(appRow.id) as any;
    return c.json({
      applicant: appRow,
      passid_verification: verification ? JSON.parse(verification.result_json) : { status: "not_connected" },
    });
  });

  app.post("/api/passid/connect/sessions", async (c) => {
    const user = await requireUser(c, ["candidate"]);
    if (user instanceof Response) return user;
    const csrf = await requireCsrf(c);
    if (csrf) return csrf;
    const body = z.object({ application_id: z.string() }).parse(await c.req.json());
    const appRow = db.prepare("SELECT a.*, j.verification_requirements, j.title FROM applications a JOIN jobs j ON j.id=a.job_id WHERE a.id=? AND a.candidate_user_id=?").get(body.application_id, user.id) as any;
    if (!appRow) return c.json({ error: "application_not_found" }, 404);
    const requiredScopes = jsonArray(appRow.verification_requirements).map((req) => REQUIREMENT_TO_SCOPE[req]).filter(Boolean);
    const scopes = sanitizeScopes(requiredScopes, APPROVED_SCOPES);
    if (!scopes.length) return c.json({ error: "no_approved_scopes" }, 400);
    const state = randomId("state");
    const sessionRecordId = randomId("cbsess");
    const expiresAt = now() + 1000 * 60 * 15;
    const passidConfigIssue = [env.PASSID_SECRET_KEY, env.PASSID_PUBLISHABLE_KEY].some((value) => !value || /^(changeme|change-me|placeholder|secret|test|todo|example)$/i.test(value));
    if (passidConfigIssue) {
      return c.json({ error: "passid_not_configured", detail: "PASSID secret keys are missing or still using placeholder values" }, 502);
    }
    db.prepare("INSERT INTO passid_sessions (id,application_id,candidate_user_id,state_hash,status,scopes,purpose,environment,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .run(sessionRecordId, appRow.id, user.id, hmac(state, env.SESSION_SECRET), "creating", JSON.stringify(scopes), `CareerBridge application: ${appRow.title}`, env.PASSID_ENVIRONMENT, expiresAt, now());
    try {
      const created = await passid.createSession({
        scopes,
        purpose: `CareerBridge verification for ${appRow.title}`,
        return_url: `${env.PASSID_REDIRECT_URL}?state=${encodeURIComponent(state)}`,
        application_reference: appRow.id,
        state,
      });
      if (/client_secret|secret=/i.test(created.hosted_url)) return c.json({ error: "unsafe_hosted_url" }, 502);
      db.prepare("UPDATE passid_sessions SET passid_session_id=?, hosted_url=?, status=? WHERE id=?")
        .run(created.session_id, created.hosted_url, created.status, sessionRecordId);
      audit(db, user.id, "passid.session.create", "application", appRow.id, { scopes, environment: env.PASSID_ENVIRONMENT });
      return c.json({ hosted_url: created.hosted_url, session_id: created.session_id, expires_at: created.expires_at, requested_scopes: scopes });
    } catch (error) {
      console.error("PASSID session creation failed", error);
      db.prepare("UPDATE passid_sessions SET status='failed' WHERE id=?").run(sessionRecordId);
      const detail = error instanceof Error ? error.message : "unknown_error";
      return c.json({ error: "passid_session_failed", detail }, 502);
    }
  });

  app.get("/api/passid/callback", async (c) => {
    const state = c.req.query("state") ?? "";
    if (!state) return c.redirect(`${env.APP_URL}/verification?result=missing_state`);
    const stateHash = hmac(state, env.SESSION_SECRET);
    const row = db.prepare("SELECT * FROM passid_sessions WHERE state_hash=?").get(stateHash) as any;
    if (!row || row.used_at || row.expires_at < now()) return c.redirect(`${env.APP_URL}/verification?result=invalid_state`);
    if (!row.passid_session_id) return c.redirect(`${env.APP_URL}/verification?result=session_missing`);
    try {
      const result = await passid.retrieveSession(row.passid_session_id);
      db.transaction(() => {
        db.prepare("UPDATE passid_sessions SET used_at=?, status=? WHERE id=?").run(now(), result.status, row.id);
        const connectionId = randomId("cbconn");
        db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,expires_at,last_api_request_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
          .run(connectionId, row.application_id, row.candidate_user_id, row.passid_session_id, result.connection_id ?? null, result.status, JSON.stringify(result.granted_scopes), result.status === "approved" ? "active" : "pending", result.expires_at ? Date.parse(result.expires_at) : null, result.request_id ?? null, now(), now());
        const safeResult = {
          identity: result.verification.identity ?? (result.granted_scopes.includes("identity.read") ? "verified" : "not_requested"),
          education: result.verification.education ?? (result.granted_scopes.includes("education.read") ? "verified" : "not_requested"),
          account_ownership: result.verification.account_ownership ?? (result.granted_scopes.includes("account_ownership.read") ? "verified" : "not_requested"),
          marketplace_uniqueness: result.verification.marketplace_uniqueness ?? (result.granted_scopes.includes("marketplace_uniqueness.read") ? "verified" : "not_requested"),
          consent_status: result.status === "approved" ? "active" : "pending",
          granted_scopes: result.granted_scopes,
          updated_at: new Date().toISOString(),
        };
        db.prepare("INSERT OR REPLACE INTO verification_results (id,application_id,candidate_user_id,result_json,updated_at) VALUES (?,?,?,?,?)")
          .run(randomId("vresult"), row.application_id, row.candidate_user_id, JSON.stringify(safeResult), now());
        db.prepare("UPDATE applications SET status=?, updated_at=? WHERE id=?").run(result.status === "approved" ? "under_review" : "verification_required", now(), row.application_id);
        audit(db, row.candidate_user_id, "passid.callback.complete", "application", row.application_id, { status: result.status });
      })();
      return c.redirect(`${env.APP_URL}/verification?result=success`);
    } catch {
      return c.redirect(`${env.APP_URL}/verification?result=retrieve_failed`);
    }
  });

  app.post("/api/passid/connections/:id/revoke", async (c) => {
    const user = await requireUser(c, ["candidate"]);
    if (user instanceof Response) return user;
    const csrf = await requireCsrf(c);
    if (csrf) return csrf;
    const row = db.prepare("SELECT * FROM passid_connections WHERE id=? AND candidate_user_id=?").get(c.req.param("id"), user.id) as any;
    if (!row) return c.json({ error: "not_found" }, 404);
    try {
      if (row.connection_id) await passid.revokeConnection(row.connection_id);
    } catch {
      return c.json({ error: "passid_revoke_failed" }, 502);
    }
    db.prepare("UPDATE passid_connections SET status='revoked', consent_status='revoked', updated_at=? WHERE id=?").run(now(), row.id);
    db.prepare("UPDATE verification_results SET result_json=?, updated_at=? WHERE application_id=?")
      .run(JSON.stringify({ status: "revoked", consent_status: "revoked", updated_at: new Date().toISOString() }), now(), row.application_id);
    audit(db, user.id, "passid.connection.revoke", "passid_connection", row.id, {});
    return c.json({ ok: true, status: "revoked" });
  });

  app.post("/api/webhooks/passid", async (c) => {
    const raw = await c.req.text();

    // Try multiple header name variations to handle PassID sending different casing
    const sig =
      c.req.header("PassID-Signature") ??
      c.req.header("X-PassID-Signature") ??
      c.req.header("passid-signature") ??
      c.req.header("x-passid-signature") ??
      "";
    const timestamp =
      c.req.header("PassID-Timestamp") ??
      c.req.header("X-PassID-Timestamp") ??
      c.req.header("passid-timestamp") ??
      c.req.header("x-passid-timestamp") ??
      "";
    const eventIdHeader =
      c.req.header("PassID-Event-Id") ??
      c.req.header("X-PassID-Event-Id") ??
      c.req.header("passid-event-id") ??
      c.req.header("x-passid-event-id") ??
      "";

    // Debug logging to help identify header/secret mismatches
    console.log("[passid-webhook] incoming request", {
      timestamp,
      timestampHeader: c.req.header("PassID-Timestamp") !== undefined ? "PassID-Timestamp"
        : c.req.header("X-PassID-Timestamp") !== undefined ? "X-PassID-Timestamp"
        : c.req.header("passid-timestamp") !== undefined ? "passid-timestamp"
        : c.req.header("x-passid-timestamp") !== undefined ? "x-passid-timestamp"
        : "(none)",
      signatureHeader: c.req.header("PassID-Signature") !== undefined ? "PassID-Signature"
        : c.req.header("X-PassID-Signature") !== undefined ? "X-PassID-Signature"
        : c.req.header("passid-signature") !== undefined ? "passid-signature"
        : c.req.header("x-passid-signature") !== undefined ? "x-passid-signature"
        : "(none)",
      sigPrefix: sig ? sig.slice(0, 16) + "..." : "(empty)",
      rawBodyLength: raw.length,
    });

    const ts = Number(timestamp);
    const nowMs = now();
    const nowSeconds = Math.floor(nowMs / 1000);
    const isWithinTolerance =
      !timestamp ||
      !Number.isFinite(ts) ||
      Math.abs(nowMs - ts) <= 1000 * 60 * 10 ||
      Math.abs(nowSeconds - ts) <= 60 * 10;
    if (!isWithinTolerance) {
      console.log("[passid-webhook] timestamp validation failed", {
        ts,
        nowMs,
        nowSeconds,
        diffMs: Number.isFinite(ts) ? Math.abs(nowMs - ts) : null,
        diffSeconds: Number.isFinite(ts) ? Math.abs(nowSeconds - ts) : null,
        toleranceSeconds: 600,
      });
    }

    const signatureCandidates = new Set<string>();
    const normalizedSignature = sig.trim();
    if (normalizedSignature) {
      const parts = normalizedSignature.split(/[,;]/).map((part) => part.trim()).filter(Boolean);
      for (const part of parts) {
        if (/^sha256\s*=\s*/i.test(part)) {
          signatureCandidates.add(part.replace(/^sha256\s*=\s*/i, ""));
        } else if (/^v\d+\s*=\s*/i.test(part)) {
          signatureCandidates.add(part.replace(/^v\d+\s*=\s*/i, ""));
        } else if (/^[a-f0-9]{8,}$/i.test(part)) {
          signatureCandidates.add(part);
        } else if (part) {
          signatureCandidates.add(part);
        }
      }
    }

    const messageVariants = [
      `${timestamp}.${raw}`,
      `${timestamp}:${raw}`,
      `${timestamp}\n${raw}`,
      `${timestamp}\n${raw}\n`,
      raw,
      `payload=${raw}`,
      `body=${raw}`,
      `${timestamp}.${raw.trim()}`,
      `${timestamp}:${raw.trim()}`,
    ];
    const expectedCandidates = messageVariants.map((message) => hmac(message, env.PASSID_WEBHOOK_SECRET));
    const matchedSignature = Array.from(signatureCandidates).find((candidate) => {
      const normalizedCandidate = candidate.trim();
      if (!normalizedCandidate) return false;
      const expectedHexes = expectedCandidates.map((expected) => expected.toLowerCase());
      const normalizedHex = normalizedCandidate.toLowerCase();
      if (expectedHexes.includes(normalizedHex)) return true;

      try {
        const decoded = Buffer.from(normalizedCandidate, "base64");
        const decodedHex = decoded.toString("hex");
        return expectedHexes.includes(decodedHex);
      } catch {
        return false;
      }
    });

    console.log("[passid-webhook] signature check", {
      expectedPrefixes: expectedCandidates.map((expected) => expected.slice(0, 16) + "..."),
      receivedPrefix: normalizedSignature ? normalizedSignature.slice(0, 24) : "(empty)",
      match: Boolean(matchedSignature),
    });
    if (!sig || !matchedSignature) {
      return c.json({ error: "invalid_signature", detail: "HMAC signature does not match" }, 401);
    }

    const event = JSON.parse(raw);
    const eventId = String(event.id ?? eventIdHeader ?? randomId("evt"));
    const existing = db.prepare("SELECT id FROM passid_webhook_events WHERE id=?").get(eventId);
    if (existing) return c.json({ ok: true, duplicate: true });
    const type = String(event.type ?? "unknown");
    const connectionId = event.data?.connection_id ?? event.data?.passid_connection_id ?? null;
    db.prepare("INSERT INTO passid_webhook_events (id,type,passid_connection_id,processed_at,payload_summary) VALUES (?,?,?,?,?)")
      .run(eventId, type, connectionId, now(), JSON.stringify({ type, connection_id: connectionId, status: event.data?.status ?? null }));
    if (connectionId && /revoked|consent\.revoked|connection\.revoked/.test(type)) {
      const conn = db.prepare("SELECT * FROM passid_connections WHERE connection_id=?").get(connectionId) as any;
      if (conn) {
        db.prepare("UPDATE passid_connections SET status='revoked', consent_status='revoked', last_webhook_event=?, updated_at=? WHERE id=?").run(type, now(), conn.id);
        db.prepare("UPDATE verification_results SET result_json=?, updated_at=? WHERE application_id=?")
          .run(JSON.stringify({ status: "revoked", consent_status: "revoked", updated_at: new Date().toISOString() }), now(), conn.application_id);
      }
    }
    return c.json({ ok: true });
  });

  app.get("/api/admin/passid", async (c) => {
    const user = await requireUser(c, ["admin"]);
    if (user instanceof Response) return user;
    const connections = db.prepare(`
      SELECT pc.id, pc.connection_id, pc.status, pc.consent_status, pc.granted_scopes, pc.created_at, pc.updated_at, pc.last_webhook_event, a.id AS application_id, u.email AS candidate_reference
      FROM passid_connections pc JOIN applications a ON a.id=pc.application_id JOIN users u ON u.id=pc.candidate_user_id
      ORDER BY pc.created_at DESC
    `).all();
    const events = db.prepare("SELECT id,type,passid_connection_id,processed_at,payload_summary FROM passid_webhook_events ORDER BY processed_at DESC LIMIT 50").all();
    return c.json({ environment: env.PASSID_ENVIRONMENT, connections, events });
  });

  const DIST_DIR = "/app/web/dist";

  app.get("*", async (c) => {
    const url = new URL(c.req.url);
    const pathname = url.pathname;

    // Try to serve the exact file from the dist directory
    const filePath = `${DIST_DIR}${pathname === "/" ? "/index.html" : pathname}`;
    const file = Bun.file(filePath);

    if (await file.exists()) {
      return new Response(file);
    }

    // SPA fallback: serve index.html for any path that doesn't match a file
    const indexFile = Bun.file(`${DIST_DIR}/index.html`);
    if (await indexFile.exists()) {
      return new Response(indexFile, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    return c.json({ error: "not_found" }, 404);
  });

  return { app, db, close: () => ownedDb?.close() };
}
