import { Hono } from "hono";
import { cors } from "hono/cors";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { z } from "zod";
import type { Database } from "bun:sqlite";
import { createHash } from "crypto";
import { join, normalize, extname } from "path";
import { openCareerBridgeDb, type Role } from "./db";
import { getEnvironmentIssues, loadEnv, safeVersion, type CareerBridgeEnv } from "./env";
import { createPassidClient, type PassidClient } from "./passid";
import { hashPassword, hmac, randomId, safeEqual, sanitizeScopes, verifyPassword } from "./security";

const APPROVED_SCOPES = [
  "identity.read",
  "verification_status.read",
  "accounts.read",
  "income.read",
];

const REQUIREMENT_TO_SCOPE: Record<string, string> = {
  identity_verified: "identity.read",
  income_verification: "income.read",
  account_ownership: "accounts.read",
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

function passidReturnUrl(baseUrl: string, state: string): string {
  const url = new URL(baseUrl);
  url.searchParams.set("state", state);
  return url.toString();
}

function isSafePassidHostedUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && (url.hostname === "passid.io" || url.hostname.endsWith(".passid.io"));
  } catch {
    return false;
  }
}

function audit(db: Database, actor: string | null, action: string, targetType: string, targetId: string, detail: Record<string, unknown>) {
  db.prepare("INSERT INTO audit_logs (id,actor_user_id,action,target_type,target_id,detail_json,created_at) VALUES (?,?,?,?,?,?,?)")
    .run(randomId("audit"), actor, action, targetType, targetId, JSON.stringify(detail), now());
}

function publicUser(user: User) {
  return { id: user.id, email: user.email, role: user.role, name: user.name };
}

function contentType(path: string): string {
  switch (extname(path)) {
    case ".html": return "text/html; charset=utf-8";
    case ".js": return "text/javascript; charset=utf-8";
    case ".css": return "text/css; charset=utf-8";
    case ".svg": return "image/svg+xml";
    case ".png": return "image/png";
    case ".ico": return "image/x-icon";
    case ".json": return "application/json; charset=utf-8";
    default: return "application/octet-stream";
  }
}

async function serveCareerBridgeWeb(c: any) {
  const distDir = normalize(join(process.cwd(), "../web/dist"));
  const url = new URL(c.req.url);
  const requestedPath = decodeURIComponent(url.pathname);
  const relative = requestedPath === "/" ? "index.html" : requestedPath.replace(/^\/+/, "");
  const candidate = normalize(join(distDir, relative));
  const safePath = candidate.startsWith(distDir) ? candidate : join(distDir, "index.html");
  const file = Bun.file(safePath);
  const exists = await file.exists();
  const finalPath = exists ? safePath : join(distDir, "index.html");
  const finalFile = Bun.file(finalPath);
  if (!(await finalFile.exists())) return c.json({ error: "web_build_not_found" }, 404);
  return new Response(finalFile, {
    headers: {
      "Content-Type": contentType(finalPath),
      "Cache-Control": finalPath.endsWith("index.html") ? "no-cache" : "public, max-age=31536000, immutable",
    },
  });
}

export function createCareerBridgeApp(options: AppOptions = {}) {
  const env = options.env ?? loadEnv();
  const ownedDb = options.db ? null : openCareerBridgeDb(env.DATABASE_URL);
  const db = options.db ?? ownedDb!.db;
  const passid = options.passidClient ?? createPassidClient(env);
  const app = new Hono();

  function createUserSession(c: any, user: User) {
    const sessionId = randomId("sess");
    const csrf = randomId("csrf");
    db.prepare("INSERT INTO sessions (id,user_id,csrf,expires_at,created_at) VALUES (?,?,?,?,?)").run(sessionId, user.id, csrf, now() + 1000 * 60 * 60 * 8, now());
    setCookie(c, "cb_session", sessionId, { httpOnly: true, secure: env.NODE_ENV === "production", sameSite: "Lax", path: "/", maxAge: 60 * 60 * 8 });
    return { csrf };
  }

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
    approvedScopes: APPROVED_SCOPES,
  }));
  app.get("/api/admin/environment", async (c) => {
    const user = await requireUser(c, ["admin"]);
    if (user instanceof Response) return user;
    return c.json({ issues: getEnvironmentIssues(process.env).map((issue) => issue.split(":")[0]), passidEnvironment: env.PASSID_ENVIRONMENT });
  });

  app.post("/api/auth/signup", async (c) => {
    const parsed = z.object({
      email: z.string().trim().email().max(254),
      password: z.string().min(12).max(128)
        .regex(/[a-z]/, "password_requires_lowercase")
        .regex(/[A-Z]/, "password_requires_uppercase")
        .regex(/[0-9]/, "password_requires_number"),
      name: z.string().trim().min(2).max(100),
      role: z.enum(["candidate", "employer"]),
      organization_name: z.preprocess(
        (value) => typeof value === "string" && value.trim() === "" ? undefined : value,
        z.string().trim().min(2).max(160).optional(),
      ),
      website: z.preprocess(
        (value) => typeof value === "string" && value.trim() === "" ? undefined : value,
        z.string().trim().url().max(300).optional(),
      ),
      accepted_terms: z.literal(true),
    }).safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: "invalid_signup", fields: parsed.error.flatten().fieldErrors }, 400);
    const body = parsed.data;
    if (body.role === "employer" && !body.organization_name) {
      return c.json({ error: "organization_name_required" }, 400);
    }
    const id = randomId("usr");
    try {
      db.transaction(() => {
        db.prepare("INSERT INTO users (id,email,password_hash,role,name,email_verified,created_at) VALUES (?,?,?,?,?,0,?)")
          .run(id, body.email.toLowerCase(), hashPassword(body.password), body.role, body.name, now());
        if (body.role === "candidate") db.prepare("INSERT INTO candidate_profiles (user_id) VALUES (?)").run(id);
        if (body.role === "employer") {
          db.prepare("INSERT INTO organizations (id,owner_user_id,name,type,status,website,created_at) VALUES (?,?,?,?,?,?,?)")
            .run(randomId("org"), id, body.organization_name!, "employer", "pending", body.website || null, now());
        }
      })();
      const { csrf } = createUserSession(c, { id, email: body.email.toLowerCase(), role: body.role, name: body.name });
      audit(db, id, "user.signup", "user", id, { role: body.role, terms_accepted: true });
      return c.json({ user: { id, email: body.email.toLowerCase(), role: body.role, name: body.name }, csrf }, 201);
    } catch {
      return c.json({ error: "email_unavailable" }, 409);
    }
  });

  app.post("/api/auth/login", async (c) => {
    const parsed = z.object({ email: z.string().trim().email(), password: z.string().min(1) })
      .safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: "invalid_login", message: "Enter a valid email address and password." }, 400);
    const body = parsed.data;
    const user = db.prepare("SELECT id,email,password_hash,role,name,suspended_at FROM users WHERE email = ?").get(body.email.toLowerCase()) as any;
    const demoOk = env.NODE_ENV !== "production" && user?.password_hash === "pbkdf2$demo$demo" && body.password === "CareerBridgeDemo!2026";
    if (!user || user.suspended_at || (!demoOk && !verifyPassword(body.password, user.password_hash))) {
      return c.json({ error: "invalid_credentials" }, 401);
    }
    const { csrf } = createUserSession(c, user);
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

  app.get("/api/employer/jobs", async (c) => {
    const user = await requireUser(c, ["employer", "admin"]);
    if (user instanceof Response) return user;
    const rows = user.role === "admin"
      ? db.prepare(`
          SELECT j.*, o.name AS organization_name
          FROM jobs j JOIN organizations o ON o.id = j.organization_id
          ORDER BY j.created_at DESC
        `).all()
      : db.prepare(`
          SELECT j.*, o.name AS organization_name
          FROM jobs j JOIN organizations o ON o.id = j.organization_id
          WHERE o.owner_user_id = ?
          ORDER BY j.created_at DESC
        `).all(user.id);
    return c.json({ jobs: rows.map((job: any) => ({ ...job, verification_requirements: jsonArray(job.verification_requirements) })) });
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

    const existingSession = db.prepare(`
      SELECT passid_session_id, hosted_url, expires_at, scopes, status
      FROM passid_sessions
      WHERE application_id=? AND candidate_user_id=? AND expires_at > ? AND status != 'failed'
      ORDER BY created_at DESC
      LIMIT 1
    `).get(appRow.id, user.id, now()) as any;
    if (existingSession?.status === "creating") {
      return c.json({ error: "session_creation_in_progress" }, 409);
    }
    if (existingSession?.hosted_url && existingSession?.passid_session_id) {
      return c.json({
        hosted_url: existingSession.hosted_url,
        session_id: existingSession.passid_session_id,
        expires_at: new Date(Number(existingSession.expires_at)).toISOString(),
        requested_scopes: jsonArray(existingSession.scopes),
        reused: true,
      });
    }

    const state = randomId("state");
    const sessionRecordId = randomId("cbsess");
    const expiresAt = now() + 1000 * 60 * 15;
    db.prepare("INSERT INTO passid_sessions (id,application_id,candidate_user_id,state_hash,status,scopes,purpose,environment,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .run(sessionRecordId, appRow.id, user.id, hmac(state, env.SESSION_SECRET), "creating", JSON.stringify(scopes), `CareerBridge application: ${appRow.title}`, env.PASSID_ENVIRONMENT, expiresAt, now());
    try {
      const created = await passid.createSession({
        scopes,
        purpose: `CareerBridge verification for ${appRow.title}`,
        return_url: passidReturnUrl(env.PASSID_REDIRECT_URL, state),
        application_reference: appRow.id,
        idempotency_key: sessionRecordId,
        access_duration: "90days",
      });
      if (!isSafePassidHostedUrl(created.hosted_url) || /client_secret|secret=/i.test(created.hosted_url)) {
        throw new Error("PASSID_UNSAFE_HOSTED_URL");
      }
      const upstreamExpiry = created.expires_at ? Date.parse(created.expires_at) : NaN;
      const effectiveExpiry = Number.isFinite(upstreamExpiry) ? Math.min(expiresAt, upstreamExpiry) : expiresAt;
      db.prepare("UPDATE passid_sessions SET passid_session_id=?, hosted_url=?, status=?, expires_at=? WHERE id=?")
        .run(created.session_id, created.hosted_url, created.status, effectiveExpiry, sessionRecordId);
      audit(db, user.id, "passid.session.create", "application", appRow.id, { scopes, environment: env.PASSID_ENVIRONMENT });
      return c.json({
        hosted_url: created.hosted_url,
        session_id: created.session_id,
        expires_at: new Date(effectiveExpiry).toISOString(),
        requested_scopes: scopes,
      });
    } catch (error) {
      db.prepare("UPDATE passid_sessions SET status='failed' WHERE id=?").run(sessionRecordId);
      const errorBody = (error as any)?.body ?? {};
      console.error("[passid.session.create error]", { 
        status: (error as any)?.status,
        code: errorBody?.error?.code,
        requestId: (error as any)?.requestId
      });
      const status = (error as any)?.status === 429 ? 429 : 502;
      const retryAfterSeconds = (error as any)?.retryAfterSeconds;
      if (status === 429) {
        if (retryAfterSeconds != null) c.header("Retry-After", String(retryAfterSeconds));
        return c.json({
          error: "passid_rate_limited",
          message: "PASSID is rate limiting session creation. Please retry shortly.",
          retry_after_seconds: retryAfterSeconds ?? 60,
          passid_request_id: (error as any)?.requestId,
        }, 429);
      }
      return c.json({
        error: "passid_session_failed",
        message: "Could not create a PASSID session. Please retry shortly.",
        passid_request_id: (error as any)?.requestId,
      }, status);
    }
  });

  app.get("/api/passid/callback", async (c) => {
    const state = c.req.query("state") ?? "";
    if (!state) return c.redirect(`${env.APP_URL}/verification?result=missing_state`);
    const stateHash = hmac(state, env.SESSION_SECRET);
    const row = db.prepare("SELECT * FROM passid_sessions WHERE state_hash=?").get(stateHash) as any;
    if (!row || row.used_at || row.expires_at < now()) return c.redirect(`${env.APP_URL}/verification?result=invalid_state`);
    if (!row.passid_session_id) return c.redirect(`${env.APP_URL}/verification?result=session_missing`);
    const callbackSessionId = c.req.query("session_id");
    if (callbackSessionId && callbackSessionId !== row.passid_session_id) {
      return c.redirect(`${env.APP_URL}/verification?result=invalid_state`);
    }
    try {
      const result = await passid.retrieveSession(row.passid_session_id);
      if (result.session_id !== row.passid_session_id) {
        return c.redirect(`${env.APP_URL}/verification?result=session_mismatch`);
      }
      if (result.status === "pending" || result.status === "pending_customer") {
        return c.redirect(`${env.APP_URL}/verification?result=pending`);
      }
      if (result.status !== "approved") {
        db.prepare("UPDATE passid_sessions SET used_at=?, status=? WHERE id=? AND used_at IS NULL").run(now(), result.status, row.id);
        audit(db, row.candidate_user_id, "passid.callback.complete", "application", row.application_id, { status: result.status });
        return c.redirect(`${env.APP_URL}/verification?result=${encodeURIComponent(result.status)}`);
      }
      if (!result.connection_id) throw new Error("PASSID_APPROVED_WITHOUT_CONNECTION");

      const requestedScopes = jsonArray(row.scopes);
      const grantedScopes = sanitizeScopes(result.granted_scopes, requestedScopes);
      const committed = db.transaction(() => {
        const update = db.prepare("UPDATE passid_sessions SET used_at=?, status=? WHERE id=? AND used_at IS NULL").run(now(), result.status, row.id);
        if (update.changes !== 1) return false;
        const connectionId = randomId("cbconn");
        db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,expires_at,last_api_request_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
          .run(connectionId, row.application_id, row.candidate_user_id, row.passid_session_id, result.connection_id, result.status, JSON.stringify(grantedScopes), "active", result.expires_at ? Date.parse(result.expires_at) : null, result.request_id ?? null, now(), now());
        const scopeStatus = (scope: string, key: string) => requestedScopes.includes(scope)
          ? (grantedScopes.includes(scope) ? (result.verification[key] ?? "available") : "not_granted")
          : "not_requested";
        const safeResult = {
          identity: scopeStatus("identity.read", "identity"),
          income: scopeStatus("income.read", "income"),
          account_ownership: scopeStatus("accounts.read", "account_ownership"),
          verification_status: scopeStatus("verification_status.read", "verification_status"),
          consent_status: "active",
          granted_scopes: grantedScopes,
          updated_at: new Date().toISOString(),
        };
        const requiredStatuses = [
          ["identity.read", safeResult.identity],
          ["income.read", safeResult.income],
          ["accounts.read", safeResult.account_ownership],
          ["verification_status.read", safeResult.verification_status],
        ].filter(([scope]) => requestedScopes.includes(scope));
        const verificationComplete = requiredStatuses.every(([, status]) =>
          !["not_granted", "not_verified", "unavailable"].includes(status),
        );
        db.prepare("INSERT OR REPLACE INTO verification_results (id,application_id,candidate_user_id,result_json,updated_at) VALUES (?,?,?,?,?)")
          .run(randomId("vresult"), row.application_id, row.candidate_user_id, JSON.stringify(safeResult), now());
        db.prepare("UPDATE applications SET status=?, updated_at=? WHERE id=?").run(verificationComplete ? "under_review" : "verification_required", now(), row.application_id);
        audit(db, row.candidate_user_id, "passid.callback.complete", "application", row.application_id, {
          status: result.status,
          verification_complete: verificationComplete,
        });
        return verificationComplete ? "complete" : "partial";
      })();
      if (!committed) return c.redirect(`${env.APP_URL}/verification?result=invalid_state`);
      return c.redirect(`${env.APP_URL}/verification?result=${committed === "complete" ? "success" : "partial_consent"}`);
    } catch {
      return c.redirect(`${env.APP_URL}/verification?result=retrieve_failed`);
    }
  });

  app.get("/api/passid/connections", async (c) => {
    const user = await requireUser(c, ["candidate"]);
    if (user instanceof Response) return user;
    const connections = db.prepare(`
      SELECT pc.id, pc.application_id, pc.status, pc.consent_status, pc.granted_scopes,
             pc.expires_at, pc.created_at, pc.updated_at, j.title
      FROM passid_connections pc
      JOIN applications a ON a.id=pc.application_id
      JOIN jobs j ON j.id=a.job_id
      WHERE pc.candidate_user_id=?
      ORDER BY pc.created_at DESC
    `).all(user.id) as any[];
    return c.json({
      connections: connections.map((connection) => ({
        ...connection,
        granted_scopes: jsonArray(connection.granted_scopes),
      })),
    });
  });

  app.post("/api/passid/connections/:id/revoke", async (c) => {
    const user = await requireUser(c, ["candidate"]);
    if (user instanceof Response) return user;
    const csrf = await requireCsrf(c);
    if (csrf) return csrf;
    const row = db.prepare("SELECT * FROM passid_connections WHERE id=? AND candidate_user_id=?").get(c.req.param("id"), user.id) as any;
    if (!row) return c.json({ error: "not_found" }, 404);
    if (row.consent_status === "revoked") return c.json({ ok: true, status: "revoked", already_revoked: true });
    try {
      if (row.connection_id) await passid.revokeConnection(row.connection_id);
    } catch {
      return c.json({ error: "passid_revoke_failed" }, 502);
    }
    db.prepare("UPDATE passid_connections SET status='revoked', consent_status='revoked', updated_at=? WHERE id=?").run(now(), row.id);
    db.prepare("UPDATE verification_results SET result_json=?, updated_at=? WHERE application_id=?")
      .run(JSON.stringify({ status: "revoked", consent_status: "revoked", updated_at: new Date().toISOString() }), now(), row.application_id);
    db.prepare("UPDATE applications SET status='verification_required', updated_at=? WHERE id=?").run(now(), row.application_id);
    audit(db, user.id, "passid.connection.revoke", "passid_connection", row.id, {});
    return c.json({ ok: true, status: "revoked" });
  });

  async function verifyPassidWebhook(c: any) {
    const raw = Buffer.from(await c.req.arrayBuffer());
    const sig = c.req.header("x-passid-signature") ?? c.req.header("PassID-Signature") ?? "";
    const received = sig.replace(/^sha256=/, "");

    if (!/^sha256=[0-9a-f]{64}$/.test(sig)) return { ok: false as const, response: c.json({ error: "invalid_signature" }, 401) };

    const expected = hmac(raw, env.PASSID_WEBHOOK_SECRET);
    if (!safeEqual(received, expected)) return { ok: false as const, response: c.json({ error: "invalid_signature" }, 401) };

    return { ok: true as const, body: raw.toString("utf8"), bodySha256: createHash("sha256").update(raw).digest("hex") };
  }

  app.post("/api/institution/webhook-catcher", async (c) => {
    const verified = await verifyPassidWebhook(c);
    if (!verified.ok) return verified.response;
    return c.json({ ok: true, body_sha256: verified.bodySha256 });
  });

  app.post("/api/webhooks/passid", async (c) => {
    const verified = await verifyPassidWebhook(c);
    if (!verified.ok) return verified.response;
    const eventIdHeader = c.req.header("x-passid-event") ?? c.req.header("PassID-Event") ?? "";

    let event: any;
    try {
      event = JSON.parse(verified.body);
    } catch {
      return c.json({ error: "invalid_json" }, 400);
    }
    const eventId = String(event.event_id ?? event.id ?? "");
    if (!eventId) return c.json({ error: "missing_event_id" }, 400);
    const existing = db.prepare("SELECT id FROM passid_webhook_events WHERE id=?").get(eventId);
    if (existing) return c.json({ ok: true, duplicate: true });
    const type = String(event.event_type ?? event.type ?? eventIdHeader ?? "unknown");
    const connectionId = event.data?.connection_id ?? event.data?.passid_connection_id ?? null;
    db.prepare("INSERT INTO passid_webhook_events (id,type,passid_connection_id,processed_at,payload_summary) VALUES (?,?,?,?,?)")
      .run(eventId, type, connectionId, now(), JSON.stringify({ type, connection_id: connectionId, status: event.data?.status ?? null }));
    if (connectionId && /revoked|consent\.revoked|connection\.revoked|connection\.expired/.test(type)) {
      const conn = db.prepare("SELECT * FROM passid_connections WHERE connection_id=?").get(connectionId) as any;
      if (conn) {
        const lifecycleStatus = type === "connection.expired" ? "expired" : "revoked";
        db.prepare("UPDATE passid_connections SET status=?, consent_status=?, last_webhook_event=?, updated_at=? WHERE id=?").run(lifecycleStatus, lifecycleStatus, type, now(), conn.id);
        db.prepare("UPDATE verification_results SET result_json=?, updated_at=? WHERE application_id=?")
          .run(JSON.stringify({ status: lifecycleStatus, consent_status: lifecycleStatus, updated_at: new Date().toISOString() }), now(), conn.application_id);
        db.prepare("UPDATE applications SET status='verification_required', updated_at=? WHERE id=?").run(now(), conn.application_id);
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

  app.get("/api/admin/passid/readiness", async (c) => {
    const user = await requireUser(c, ["admin"]);
    if (user instanceof Response) return user;
    try {
      const result = await passid.checkConnection();
      return c.json({ ok: result.active, environment: result.environment ?? env.PASSID_ENVIRONMENT, request_id: result.request_id ?? null });
    } catch (error) {
      return c.json({
        ok: false,
        environment: env.PASSID_ENVIRONMENT,
        error: (error as any)?.status === 401 ? "invalid_or_inactive_connect_key" : "passid_unreachable",
        request_id: (error as any)?.requestId ?? null,
      }, 502);
    }
  });

  app.get("*", serveCareerBridgeWeb);

  return { app, db, close: () => ownedDb?.close() };
}
