import { beforeEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "crypto";
import { createCareerBridgeApp } from "../src/app";
import { migrate, seed } from "../src/db";
import type { CareerBridgeEnv } from "../src/env";
import { createPkcePair, decryptSecret, encryptSecret, hmac, randomId } from "../src/security";
import { createPassidClient, type PassidClient } from "../src/passid";

const baseEnv: CareerBridgeEnv = {
  NODE_ENV: "test",
  PORT: 4100,
  APP_URL: "https://careerbridge.test",
  API_URL: "https://api.careerbridge.test",
  DATABASE_URL: ":memory:",
  SESSION_SECRET: "test_session_secret_32_bytes_long",
  ENCRYPTION_KEY: "test_encryption_key_32_bytes_long",
  PASSID_API_BASE_URL: "https://api.passid.io/api/sandbox/connect",
  PASSID_SECRET_KEY: "sk_test_careerbridge_safe_test_key",
  PASSID_PUBLISHABLE_KEY: "pk_test_careerbridge",
  PASSID_WEBHOOK_SECRET: "whsec_test_careerbridge_very_secret",
  PASSID_ENVIRONMENT: "sandbox",
  PASSID_REDIRECT_URL: "https://api.careerbridge.test/api/passid/callback",
  PASSID_WEBHOOK_URL: "https://api.careerbridge.test/api/webhooks/passid",
  PASSID_PAY_PREVIEW_ENABLED: true,
  RESEND_API_KEY: "",
  PASSWORD_RESET_EMAIL_FROM: "",
};

describe("PKCE secret handling", () => {
  it("creates an S256-compatible pair and encrypts the verifier at rest", () => {
    const pair = createPkcePair();
    expect(pair.verifier.length).toBeGreaterThanOrEqual(43);
    expect(pair.verifier.length).toBeLessThanOrEqual(128);
    expect(pair.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(createHash("sha256").update(pair.verifier).digest("base64url")).toBe(pair.challenge);
    const encrypted = encryptSecret(pair.verifier, baseEnv.ENCRYPTION_KEY);
    expect(encrypted).not.toContain(pair.verifier);
    expect(decryptSecret(encrypted, baseEnv.ENCRYPTION_KEY)).toBe(pair.verifier);
  });
});

function mockPassid(): PassidClient {
  return {
    async checkConnection() {
      return { active: true, environment: "sandbox", request_id: "req_key_test" };
    },
    async createSession(input) {
      expect(input.scopes).toContain("identity.read");
      expect(input.scopes).toContain("income.read");
      expect(input.return_url).toBe(baseEnv.PASSID_REDIRECT_URL);
      expect(input.state).toStartWith("state_");
      expect(input.code_challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(input.code_challenge_method).toBe("S256");
      return {
        session_id: "pcs_sandbox_test_123",
        hosted_url: "https://passid.io/connect/authorize?env=sandbox&session=pcs_sandbox_test_123",
        status: "pending_customer",
        expires_at: new Date(Date.now() + 900_000).toISOString(),
      };
    },
    async exchangeCode(input) {
      expect(input.code_verifier.length).toBeGreaterThanOrEqual(43);
      return {
        session_id: input.session_id,
        status: "approved",
        connection_id: "conn_sandbox_test_123",
        granted_scopes: ["identity.read", "income.read"],
        verification: { identity: "verified", income: "verified" },
        request_id: "req_token_test",
        institution_subject_id: "subject_amara",
      };
    },
    async retrieveSession(sessionId) {
      return {
        session_id: sessionId,
        status: "approved",
        connection_id: "conn_sandbox_test_123",
        granted_scopes: ["identity.read", "income.read"],
        verification: { identity: "verified", income: "verified" },
        expires_at: new Date(Date.now() + 86_400_000).toISOString(),
        request_id: "req_passid_test",
      };
    },
    async revokeConnection(connectionId) {
      expect(connectionId).toBe("conn_sandbox_test_123");
      return { status: "revoked" };
    },
  };
}

function mockRateLimitedPassid(): PassidClient {
  return {
    async checkConnection() {
      throw new Error("not used");
    },
    async createSession() {
      const err = new Error("PASSID_SESSION_CREATE_FAILED:PASSID_API_429:status=429:retry_after=60s");
      (err as any).status = 429;
      (err as any).code = "PASSID_API_429";
      (err as any).retryAfterSeconds = 60;
      (err as any).requestId = "req_passid_rate_limited";
      throw err;
    },
    async exchangeCode() {
      throw new Error("not used");
    },
    async retrieveSession() {
      throw new Error("not used");
    },
    async revokeConnection() {
      throw new Error("not used");
    },
  };
}

function testApp() {
  const db = new Database(":memory:");
  migrate(db);
  seed(db);
  const created = createCareerBridgeApp({ env: baseEnv, db, passidClient: mockPassid() });
  return { ...created, db };
}

async function login(app: any, email: string, role = "candidate") {
  const password = "CareerBridgeDemo!2026";
  const res = await app.request("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  expect(res.status).toBe(200);
  const body = await res.json() as any;
  expect(body.user.role).toBe(role);
  return {
    cookie: res.headers.get("set-cookie")!.split(";")[0],
    csrf: body.csrf as string,
    user: body.user,
  };
}

async function applyToDemoJob(app: any, auth: { cookie: string; csrf: string }) {
  const res = await app.request("/api/jobs/job_demo/apply", {
    method: "POST",
    headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
    body: JSON.stringify({ cover_note: "I can support fintech marketplace operations." }),
  });
  expect(res.status).toBe(201);
  return await res.json() as any;
}

describe("CareerBridge independent PASSID institution app", () => {
  let app: any;
  let db: Database;

  beforeEach(() => {
    const created = testApp();
    app = created.app;
    db = created.db;
  });

  it("exposes safe health and version metadata", async () => {
    const health = await app.request("/health");
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: "ok", service: "careerbridge" });
    const version = await app.request("/version");
    expect(version.status).toBe(200);
    const body = await version.json() as any;
    expect(body.service).toBe("careerbridge");
    expect(JSON.stringify(body)).not.toContain("sk_test");

    const config = await app.request("/api/config");
    expect(JSON.stringify(await config.json())).not.toContain("pk_test");
  });

  it("checks the registered PassID institution key only for admins", async () => {
    const anonymous = await app.request("/api/admin/passid/readiness");
    expect(anonymous.status).toBe(401);
    const admin = await login(app, "admin@careerbridge.test", "admin");
    const readiness = await app.request("/api/admin/passid/readiness", { headers: { Cookie: admin.cookie } });
    expect(readiness.status).toBe(200);
    expect(await readiness.json()).toEqual({ ok: true, environment: "sandbox", request_id: "req_key_test" });
  });

  it("signs up a new user, returns a session, and logs out cleanly", async () => {
    const email = `new.user.${Date.now()}@careerbridge.test`;
    const signup = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "New User",
        email,
        password: "CareerBridgeDemo!2026",
        role: "candidate",
        organization_name: "",
        website: "",
        accepted_terms: true,
      }),
    });

    expect(signup.status).toBe(201);
    const signupBody = await signup.json() as any;
    expect(signupBody.user.email).toBe(email);
    expect(signupBody.user.name).toBe("New User");
    const cookie = signup.headers.get("set-cookie")!.split(";")[0];

    const me = await app.request("/api/auth/me", { headers: { Cookie: cookie } });
    expect(me.status).toBe(200);
    const meBody = await me.json() as any;
    expect(meBody.user.email).toBe(email);

    const logout = await app.request("/api/auth/logout", {
      method: "POST",
      headers: { Cookie: cookie, "Content-Type": "application/json", "X-CSRF-Token": signupBody.csrf },
    });
    expect(logout.status).toBe(200);
    expect(await logout.json()).toEqual({ ok: true });

    const afterLogout = await app.request("/api/auth/me", { headers: { Cookie: cookie } });
    expect(await afterLogout.json()).toEqual({ user: null });
  });

  it("logs in directly and rejects invalid credentials", async () => {
    const malformed = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "not-an-email", password: "anything" }),
    });
    expect(malformed.status).toBe(400);
    expect((await malformed.json() as any).error).toBe("invalid_login");

    const bad = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "amara@careerbridge.test", password: "wrong-password" }),
    });
    expect(bad.status).toBe(401);
    expect(bad.headers.get("set-cookie")).toBeNull();

    const ok = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "amara@careerbridge.test", password: "CareerBridgeDemo!2026" }),
    });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("set-cookie")).toContain("cb_session=");
    const body = await ok.json() as any;
    expect(body.user.email).toBe("amara@careerbridge.test");
    expect(body.csrf).toBeTruthy();

    const legacyVerify = await app.request("/api/auth/login/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge_id: "otp_legacy", otp: "123456" }),
    });
    expect(legacyVerify.status).toBe(404);
    expect(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_otps'").get()).toBeNull();
  });

  it("resets passwords with a hashed, expiring, one-time token and revokes existing sessions", async () => {
    const unknown = await app.request("/api/auth/password/forgot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "missing@careerbridge.test" }),
    });
    expect(unknown.status).toBe(202);
    const unknownBody = await unknown.json() as any;
    expect(unknownBody.message).toContain("If an eligible");
    expect(unknownBody.development_reset_url).toBeUndefined();

    const existingSession = await login(app, "amara@careerbridge.test");
    const forgot = await app.request("/api/auth/password/forgot", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Real-IP": "203.0.113.42" },
      body: JSON.stringify({ email: "AMARA@careerbridge.test" }),
    });
    expect(forgot.status).toBe(202);
    const forgotBody = await forgot.json() as any;
    const resetUrl = new URL(forgotBody.development_reset_url);
    const token = resetUrl.searchParams.get("token")!;
    expect(token).toStartWith("cbrst_");
    expect(JSON.stringify(db.prepare("SELECT * FROM password_reset_tokens").get())).not.toContain(token);

    const weak = await app.request("/api/auth/password/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, password: "weak" }),
    });
    expect(weak.status).toBe(400);

    const reset = await app.request("/api/auth/password/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, password: "A-New-CareerBridge-Password-2026" }),
    });
    expect(reset.status).toBe(200);
    expect((await reset.json() as any).ok).toBe(true);

    const reused = await app.request("/api/auth/password/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, password: "Another-Password-For-2026" }),
    });
    expect(reused.status).toBe(400);
    expect((await reused.json() as any).error).toBe("invalid_or_expired_reset_token");

    const revokedSession = await app.request("/api/auth/me", { headers: { Cookie: existingSession.cookie } });
    expect(await revokedSession.json()).toEqual({ user: null });
    const oldPassword = await app.request("/api/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "amara@careerbridge.test", password: "CareerBridgeDemo!2026" }),
    });
    expect(oldPassword.status).toBe(401);
    const newPassword = await app.request("/api/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "amara@careerbridge.test", password: "A-New-CareerBridge-Password-2026" }),
    });
    expect(newPassword.status).toBe(200);
  });

  it("starts in production without an email provider and degrades password recovery safely", async () => {
    const production = createCareerBridgeApp({
      env: { ...baseEnv, NODE_ENV: "production", RESEND_API_KEY: "", PASSWORD_RESET_EMAIL_FROM: "" },
      db,
      passidClient: mockPassid(),
    }).app;
    const health = await production.request("/health");
    expect(health.status).toBe(200);
    const config = await production.request("/api/config");
    expect((await config.json() as any).passwordResetAvailable).toBe(false);
    const forgot = await production.request("/api/auth/password/forgot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "amara@careerbridge.test" }),
    });
    expect(forgot.status).toBe(503);
    expect((await forgot.json() as any).error).toBe("password_reset_unavailable");
  });

  it("never accepts development demo passwords in production", async () => {
    const productionApp = createCareerBridgeApp({ env: { ...baseEnv, NODE_ENV: "production" }, db, passidClient: mockPassid() }).app;
    const response = await productionApp.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "amara@careerbridge.test", password: "CareerBridgeDemo!2026" }),
    });
    expect(response.status).toBe(401);
  });

  it("allows candidates to apply and creates a server-side PASSID session without leaking secrets", async () => {
    const jobs = await app.request("/api/jobs");
    const jobsBody = await jobs.json() as any;
    const demoJob = jobsBody.jobs.find((job: any) => job.id === "job_demo");
    expect(demoJob.verification_requirements).toContain("income_verification");

    const auth = await login(app, "amara@careerbridge.test");
    const application = await applyToDemoJob(app, auth);
    expect(application.status).toBe("verification_required");

    const connect = await app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    expect(connect.status).toBe(200);
    const body = await connect.json() as any;
    expect(body.hosted_url).toContain("/connect/authorize");
    expect(body.hosted_url).not.toContain("client_secret");
    expect(JSON.stringify(body)).not.toContain(baseEnv.PASSID_SECRET_KEY);
  });

  it("derives PASSID Pay preview readiness from active consent and verification evidence", async () => {
    const anonymous = await app.request("/api/passid/pay/readiness");
    expect(anonymous.status).toBe(401);

    const candidate = await login(app, "amara@careerbridge.test");
    const application = await applyToDemoJob(app, candidate);
    const pending = await app.request("/api/passid/pay/readiness", { headers: { Cookie: candidate.cookie } });
    expect(pending.status).toBe(200);
    expect(pending.headers.get("cache-control")).toBe("private, no-store");
    const pendingBody = await pending.json() as any;
    expect(pendingBody.product).toEqual({ mode: "private_preview", transfers_enabled: false, public_api_available: false });
    expect(pendingBody.summary.needs_verification).toBe(1);
    expect(pendingBody.applications[0].verification_state).toBe("needs_verification");

    const timestamp = Date.now();
    db.prepare("INSERT INTO passid_subject_bindings (subject_hash,candidate_user_id,status,created_at,updated_at) VALUES ('subject_hash_pay','candidate_demo','bound',?,?)").run(timestamp, timestamp);
    db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,created_at,updated_at) VALUES ('cbconn_pay',?,'candidate_demo','pcs_pay','conn_pay','approved','[\"identity.read\",\"income.read\"]','active',?,?)")
      .run(application.id, timestamp, timestamp);
    db.prepare("INSERT INTO verification_results (id,application_id,candidate_user_id,result_json,updated_at) VALUES ('vr_pay',?,'candidate_demo',?,?)")
      .run(application.id, JSON.stringify({ identity: "verified", income: "verified", consent_status: "active" }), timestamp);

    const ready = await app.request("/api/passid/pay/readiness", { headers: { Cookie: candidate.cookie } });
    const readyBody = await ready.json() as any;
    expect(readyBody.summary.verification_complete).toBe(1);
    expect(readyBody.applications[0]).toMatchObject({ verification_state: "verification_complete", identity_bound: true, consent_status: "active" });

    const employer = await login(app, "recruiter@careerbridge.test", "employer");
    const employerReadiness = await app.request("/api/passid/pay/readiness", { headers: { Cookie: employer.cookie } });
    const employerBody = await employerReadiness.json() as any;
    expect(employerBody.summary).toEqual({ total: 1, verification_complete: 1, needs_verification: 0, attention_required: 0 });
    expect(employerBody.applications).toBeUndefined();
    expect(JSON.stringify(employerBody)).not.toContain("subject_hash_pay");
  });

  it("reuses an existing pending PASSID session to avoid duplicate upstream calls", async () => {
    let createCount = 0;
    const db = new Database(":memory:");
    migrate(db);
    seed(db);
    const created = createCareerBridgeApp({
      env: baseEnv,
      db,
      passidClient: {
        ...mockPassid(),
        async createSession(input) {
          createCount += 1;
          return mockPassid().createSession(input);
        },
      },
    });
    const auth = await login(created.app, "amara@careerbridge.test");
    const application = await applyToDemoJob(created.app, auth);

    const first = await created.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    expect(first.status).toBe(200);

    const second = await created.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    expect(second.status).toBe(200);
    const body = await second.json() as any;
    expect(body.reused).toBe(true);
    expect(createCount).toBe(1);
  });

  it("returns a retryable response when a PASSID session is already being created for the application", async () => {
    const db = new Database(":memory:");
    migrate(db);
    seed(db);
    const created = createCareerBridgeApp({ env: baseEnv, db, passidClient: mockPassid() });
    const auth = await login(created.app, "amara@careerbridge.test");
    const application = await applyToDemoJob(created.app, auth);

    db.prepare("INSERT INTO passid_sessions (id,application_id,candidate_user_id,state_hash,status,scopes,purpose,environment,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .run(randomId("cbsess"), application.id, auth.user.id, hmac("state", baseEnv.SESSION_SECRET), "creating", JSON.stringify(["identity.read"]), "CareerBridge application: test", baseEnv.PASSID_ENVIRONMENT, Date.now() + 1000 * 60 * 15, Date.now());

    const res = await created.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    expect(res.status).toBe(409);
    const body = await res.json() as any;
    expect(body.error).toBe("session_creation_in_progress");
  });

  it("returns a retryable response when PASSID rate-limits session creation", async () => {
    const db = new Database(":memory:");
    migrate(db);
    seed(db);
    const created = createCareerBridgeApp({ env: baseEnv, db, passidClient: mockRateLimitedPassid() });
    const auth = await login(created.app, "amara@careerbridge.test");
    const application = await applyToDemoJob(created.app, auth);

    const res = await created.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    const body = await res.json() as any;
    expect(body.error).toBe("passid_rate_limited");
    expect(body.passid_request_id).toBe("req_passid_rate_limited");
  });

  it("validates callback state, retrieves the session server-side, and stores only permitted verification results", async () => {
    const auth = await login(app, "amara@careerbridge.test");
    const application = await applyToDemoJob(app, auth);
    await app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    const row = db.prepare("SELECT * FROM passid_sessions WHERE application_id=?").get(application.id) as any;
    const state = "state_known_for_test";
    db.prepare("UPDATE passid_sessions SET state_hash=? WHERE id=?").run(hmac(state, baseEnv.SESSION_SECRET), row.id);

    const callback = await app.request(`/api/passid/callback?state=${state}`, { redirect: "manual" });
    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toContain("result=success");

    const result = db.prepare("SELECT result_json FROM verification_results WHERE application_id=?").get(application.id) as any;
    const parsed = JSON.parse(result.result_json);
    expect(parsed.identity).toBe("verified");
    expect(parsed.income).toBe("verified");
    expect(parsed.education).toBeUndefined();
    expect(JSON.stringify(parsed)).not.toContain("bank");

    const reused = await app.request(`/api/passid/callback?state=${state}`, { redirect: "manual" });
    expect(reused.headers.get("location")).toContain("invalid_state");
  });

  it("uses PKCE and exchanges the one-time code before trusting a live callback", async () => {
    const liveDb = new Database(":memory:");
    migrate(liveDb);
    seed(liveDb);
    let savedState = "";
    let savedChallenge = "";
    let exchangeCalled = false;
    const livePassid: PassidClient = {
      ...mockPassid(),
      async createSession(input) {
        savedState = input.state;
        savedChallenge = input.code_challenge;
        expect(input.return_url).toBe(baseEnv.PASSID_REDIRECT_URL);
        expect(input.code_challenge_method).toBe("S256");
        return {
          session_id: "pcs_live_pkce",
          hosted_url: "https://app.passid.io/connect/authorize?env=live&session=pcs_live_pkce",
          status: "pending_customer",
        };
      },
      async exchangeCode(input) {
        exchangeCalled = true;
        expect(input.code).toBe("one_time_code");
        expect(input.redirect_uri).toBe(baseEnv.PASSID_REDIRECT_URL);
        expect(input.code_verifier.length).toBeGreaterThanOrEqual(43);
        expect(input.code_verifier.length).toBeLessThanOrEqual(128);
        expect(Buffer.from(input.code_verifier).toString("base64url")).not.toBe(savedChallenge);
        return {
          session_id: input.session_id,
          status: "approved",
          connection_id: "conn_live_pkce",
          granted_scopes: ["identity.read", "income.read"],
          verification: { identity: "verified", income: "verified" },
          request_id: "req_live_token",
          institution_subject_id: "subject_amara_live",
        };
      },
      async retrieveSession() {
        throw new Error("live callback must use token exchange");
      },
    };
    const created = createCareerBridgeApp({ env: { ...baseEnv, PASSID_ENVIRONMENT: "live" }, db: liveDb, passidClient: livePassid });
    const auth = await login(created.app, "amara@careerbridge.test");
    const application = await applyToDemoJob(created.app, auth);
    const sessionResponse = await created.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    expect(sessionResponse.status).toBe(200);
    const storedBefore = liveDb.prepare("SELECT pkce_verifier_ciphertext, redirect_uri FROM passid_sessions WHERE application_id=?").get(application.id) as any;
    expect(storedBefore.pkce_verifier_ciphertext).toStartWith("v1.");
    expect(storedBefore.pkce_verifier_ciphertext).not.toContain(savedChallenge);
    expect(storedBefore.redirect_uri).toBe(baseEnv.PASSID_REDIRECT_URL);

    const callback = await created.app.request(`/api/passid/callback?state=${encodeURIComponent(savedState)}&code=one_time_code&status=approved&session_id=pcs_live_pkce`, { redirect: "manual" });
    expect(callback.headers.get("location")).toContain("result=success");
    expect(exchangeCalled).toBe(true);
    const storedAfter = liveDb.prepare("SELECT pkce_verifier_ciphertext FROM passid_sessions WHERE application_id=?").get(application.id) as any;
    expect(storedAfter.pkce_verifier_ciphertext).toBeNull();
    const binding = liveDb.prepare("SELECT subject_hash,candidate_user_id FROM passid_subject_bindings").get() as any;
    expect(binding.candidate_user_id).toBe(auth.user.id);
    expect(binding.subject_hash).not.toContain("subject_amara_live");

    const repeatedSession = await created.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    expect(repeatedSession.status).toBe(409);
    expect((await repeatedSession.json() as any).error).toBe("passid_already_connected");
  });

  it("prevents one PassID identity from being attached to multiple CareerBridge accounts", async () => {
    const uniqueDb = new Database(":memory:");
    migrate(uniqueDb);
    seed(uniqueDb);
    const states: string[] = [];
    let sessionCounter = 0;
    const revoked: string[] = [];
    const uniquenessPassid: PassidClient = {
      ...mockPassid(),
      async createSession(input) {
        states.push(input.state);
        sessionCounter += 1;
        return {
          session_id: `pcs_live_unique_${sessionCounter}`,
          hosted_url: `https://app.passid.io/connect/authorize?env=live&session=pcs_live_unique_${sessionCounter}`,
          status: "pending_customer",
        };
      },
      async exchangeCode(input) {
        return {
          session_id: input.session_id,
          status: "approved",
          connection_id: `conn_${input.code}`,
          granted_scopes: ["identity.read", "income.read"],
          verification: { identity: "verified", income: "verified" },
          institution_subject_id: "same_passid_person",
        };
      },
      async revokeConnection(connectionId) {
        revoked.push(connectionId);
        return { status: "revoked" };
      },
    };
    const uniqueApp = createCareerBridgeApp({ env: { ...baseEnv, PASSID_ENVIRONMENT: "live" }, db: uniqueDb, passidClient: uniquenessPassid }).app;

    const first = await login(uniqueApp, "amara@careerbridge.test");
    const firstApplication = await applyToDemoJob(uniqueApp, first);
    await uniqueApp.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: first.cookie, "Content-Type": "application/json", "X-CSRF-Token": first.csrf },
      body: JSON.stringify({ application_id: firstApplication.id }),
    });
    const firstCallback = await uniqueApp.request(`/api/passid/callback?state=${encodeURIComponent(states[0])}&code=first&status=approved&session_id=pcs_live_unique_1`, { redirect: "manual" });
    expect(firstCallback.headers.get("location")).toContain("result=success");

    const signup = await uniqueApp.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Real-IP": "203.0.113.42" },
      body: JSON.stringify({ name: "Second Account", email: "second.account@example.com", password: "ValidPassword2026", role: "candidate", accepted_terms: true }),
    });
    expect(signup.status).toBe(201);
    const signupBody = await signup.json() as any;
    const second = { cookie: signup.headers.get("set-cookie")!.split(";")[0], csrf: signupBody.csrf, user: signupBody.user };
    const secondApplication = await applyToDemoJob(uniqueApp, second);
    await uniqueApp.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: second.cookie, "Content-Type": "application/json", "X-CSRF-Token": second.csrf },
      body: JSON.stringify({ application_id: secondApplication.id }),
    });
    const secondCallback = await uniqueApp.request(`/api/passid/callback?state=${encodeURIComponent(states[1])}&code=second&status=approved&session_id=pcs_live_unique_2`, { redirect: "manual" });
    expect(secondCallback.headers.get("location")).toContain("result=duplicate_identity");
    expect(revoked).toContain("conn_second");
    expect((uniqueDb.prepare("SELECT COUNT(*) AS count FROM passid_connections WHERE candidate_user_id=?").get(second.user.id) as any).count).toBe(0);
    expect((uniqueDb.prepare("SELECT passid_status FROM candidate_profiles WHERE user_id=?").get(second.user.id) as any).passid_status).toBe("identity_conflict");
    expect((uniqueDb.prepare("SELECT status FROM applications WHERE id=?").get(secondApplication.id) as any).status).toBe("identity_conflict");

    const blockedRetry = await uniqueApp.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: second.cookie, "Content-Type": "application/json", "X-CSRF-Token": second.csrf },
      body: JSON.stringify({ application_id: secondApplication.id }),
    });
    expect(blockedRetry.status).toBe(409);
    expect((await blockedRetry.json() as any).error).toBe("passid_identity_conflict");
  });

  it("keeps an application in verification when PASSID grants only some required scopes", async () => {
    const db = new Database(":memory:");
    migrate(db);
    seed(db);
    const partialPassid: PassidClient = {
      ...mockPassid(),
      async retrieveSession(sessionId) {
        return {
          session_id: sessionId,
          status: "approved",
          connection_id: "conn_sandbox_partial",
          granted_scopes: ["identity.read"],
          verification: { identity: "verified" },
        };
      },
    };
    const created = createCareerBridgeApp({ env: baseEnv, db, passidClient: partialPassid });
    const auth = await login(created.app, "amara@careerbridge.test");
    const application = await applyToDemoJob(created.app, auth);
    await created.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    const state = "state_partial_consent";
    db.prepare("UPDATE passid_sessions SET state_hash=? WHERE application_id=?").run(hmac(state, baseEnv.SESSION_SECRET), application.id);

    const callback = await created.app.request(`/api/passid/callback?state=${state}`, { redirect: "manual" });
    expect(callback.headers.get("location")).toContain("result=partial_consent");
    const applicationRow = db.prepare("SELECT status FROM applications WHERE id=?").get(application.id) as any;
    expect(applicationRow.status).toBe("verification_required");
    const resultRow = db.prepare("SELECT result_json FROM verification_results WHERE application_id=?").get(application.id) as any;
    expect(JSON.parse(resultRow.result_json).income).toBe("not_granted");
  });

  it("keeps employers inside their applicant boundary and shows status-oriented PASSID results only", async () => {
    const candidate = await login(app, "amara@careerbridge.test");
    const application = await applyToDemoJob(app, candidate);
    db.prepare("INSERT INTO verification_results (id,application_id,candidate_user_id,result_json,updated_at) VALUES ('vr1',?,?,?,?)")
      .run(application.id, candidate.user.id, JSON.stringify({ identity: "verified", education: "verified", consent_status: "active" }), Date.now());
    const employer = await login(app, "recruiter@careerbridge.test", "employer");
    const detail = await app.request(`/api/employer/applicants/${application.id}`, { headers: { Cookie: employer.cookie } });
    expect(detail.status).toBe(200);
    const body = await detail.json() as any;
    expect(body.passid_verification.identity).toBe("verified");
    expect(JSON.stringify(body)).not.toContain("PASSID_SECRET_KEY");

    const otherSignup = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "other@careerbridge.test", password: "A-valid-password-2026", name: "Other Recruiter", role: "employer", organization_name: "Other Company", accepted_terms: true }),
    });
    expect(otherSignup.status).toBe(201);
    db.prepare("UPDATE users SET password_hash='pbkdf2$demo$demo' WHERE email='other@careerbridge.test'").run();
    const other = await login(app, "other@careerbridge.test", "employer");
    const blocked = await app.request(`/api/employer/applicants/${application.id}`, { headers: { Cookie: other.cookie } });
    expect(blocked.status).toBe(404);
  });

  it("verifies PASSID webhooks, prevents replay, and enforces revocation", async () => {
    db.prepare("INSERT INTO applications (id,job_id,candidate_user_id,status,created_at,updated_at) VALUES ('app_webhook','job_demo','candidate_demo','under_review',?,?)").run(Date.now(), Date.now());
    db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,created_at,updated_at) VALUES ('cbconn_1','app_webhook','candidate_demo','pcs_1','conn_sandbox_test_123','approved','[\"identity.read\"]','active',?,?)").run(Date.now(), Date.now());
    db.prepare("INSERT INTO verification_results (id,application_id,candidate_user_id,result_json,updated_at) VALUES ('vr_webhook','app_webhook','candidate_demo',?,?)").run(JSON.stringify({ identity: "verified", consent_status: "active" }), Date.now());
    const createdPayload = JSON.stringify({ event_id: "evt_created_1", event_type: "connection.created", created_at: new Date().toISOString(), data: { connection_id: "conn_sandbox_test_123", institution_subject_id: "passid_subject_webhook_secret", status: "approved" } });
    const createdSig = hmac(createdPayload, baseEnv.PASSID_WEBHOOK_SECRET);
    const createdRes = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-PASSID-Signature": `sha256=${createdSig}` },
      body: createdPayload,
    });
    expect(createdRes.status).toBe(200);
    const bound = db.prepare("SELECT institution_subject_hash FROM passid_connections WHERE id='cbconn_1'").get() as any;
    expect(bound.institution_subject_hash).toBe(hmac("passid_subject_webhook_secret", baseEnv.ENCRYPTION_KEY));
    expect(JSON.stringify(db.prepare("SELECT * FROM passid_webhook_events WHERE id='evt_created_1'").get())).not.toContain("passid_subject_webhook_secret");

    const mismatchPayload = JSON.stringify({ event_id: "evt_created_2", event_type: "connection.created", created_at: new Date().toISOString(), data: { connection_id: "conn_sandbox_test_123", institution_subject_id: "different_passid_person", status: "approved" } });
    const mismatchSig = hmac(mismatchPayload, baseEnv.PASSID_WEBHOOK_SECRET);
    const mismatchRes = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-PASSID-Signature": `sha256=${mismatchSig}` },
      body: mismatchPayload,
    });
    expect(mismatchRes.status).toBe(200);
    expect((db.prepare("SELECT passid_status FROM candidate_profiles WHERE user_id='candidate_demo'").get() as any).passid_status).toBe("identity_conflict");
    expect((db.prepare("SELECT consent_status FROM passid_connections WHERE id='cbconn_1'").get() as any).consent_status).toBe("revoked");

    const payload = JSON.stringify({ event_id: "evt_1", event_type: "connection.revoked", created_at: new Date().toISOString(), data: { connection_id: "conn_sandbox_test_123", status: "revoked" } });
    const sig = hmac(payload, baseEnv.PASSID_WEBHOOK_SECRET);
    const catcher = await app.request("/api/institution/webhook-catcher", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-PASSID-Signature": `sha256=${sig}` },
      body: payload,
    });
    expect(catcher.status).toBe(200);
    expect((await catcher.json() as any).ok).toBe(true);
    const res = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-PASSID-Signature": `sha256=${sig}` },
      body: payload,
    });
    expect(res.status).toBe(200);
    const conn = db.prepare("SELECT consent_status FROM passid_connections WHERE id='cbconn_1'").get() as any;
    expect(conn.consent_status).toBe("revoked");
    const replay = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-PASSID-Signature": `sha256=${sig}` },
      body: payload,
    });
    expect((await replay.json() as any).duplicate).toBe(true);
  });

  it("rejects CSRF failures and supports candidate-driven revocation", async () => {
    const auth = await login(app, "amara@careerbridge.test");
    const application = await applyToDemoJob(app, auth);
    db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,created_at,updated_at) VALUES ('cbconn_revoke',?,?, 'pcs_1','conn_sandbox_test_123','approved','[\"identity.read\"]','active',?,?)")
      .run(application.id, auth.user.id, Date.now(), Date.now());
    const blocked = await app.request("/api/passid/connections/cbconn_revoke/revoke", { method: "POST", headers: { Cookie: auth.cookie } });
    expect(blocked.status).toBe(403);
    const ok = await app.request("/api/passid/connections/cbconn_revoke/revoke", { method: "POST", headers: { Cookie: auth.cookie, "X-CSRF-Token": auth.csrf } });
    expect(ok.status).toBe(200);
    expect((await ok.json() as any).status).toBe("revoked");
    const applicationAfterRevoke = db.prepare("SELECT status FROM applications WHERE id=?").get(application.id) as any;
    expect(applicationAfterRevoke.status).toBe("verification_required");

    const connections = await app.request("/api/passid/connections", { headers: { Cookie: auth.cookie } });
    expect(connections.status).toBe(200);
    const listed = await connections.json() as any;
    expect(listed.connections[0].id).toBe("cbconn_revoke");
    expect(listed.connections[0].granted_scopes).toEqual(["identity.read"]);

    const repeated = await app.request("/api/passid/connections/cbconn_revoke/revoke", { method: "POST", headers: { Cookie: auth.cookie, "X-CSRF-Token": auth.csrf } });
    expect(repeated.status).toBe(200);
    expect((await repeated.json() as any).already_revoked).toBe(true);
  });

  it("creates a new account and signs the user in immediately", async () => {
    const res = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "new.candidate@careerbridge.test",
        password: "A-valid-password-2026",
        name: "New Candidate",
        role: "candidate",
        accepted_terms: true,
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json() as any;
    expect(body.user.email).toBe("new.candidate@careerbridge.test");
    expect(body.user.role).toBe("candidate");
    expect(body.csrf).toBeTruthy();
    expect(res.headers.get("set-cookie")).toContain("cb_session=");

    const cookie = res.headers.get("set-cookie")!.split(";")[0];
    const me = await app.request("/api/auth/me", {
      headers: { Cookie: cookie },
    });
    expect(me.status).toBe(200);
    const meBody = await me.json() as any;
    expect(meBody.user.email).toBe("new.candidate@careerbridge.test");

    const profile = await app.request("/api/profile", {
      headers: { Cookie: cookie },
    });
    expect(profile.status).toBe(200);
    const profileBody = await profile.json() as any;
    expect(profileBody.profile.user_id).toBe(body.user.id);
  });

  it("requires real registration consent and keeps institution accounts out of public signup", async () => {
    const missingConsent = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "no.consent@example.com", password: "ValidPassword2026", name: "No Consent", role: "candidate" }),
    });
    expect(missingConsent.status).toBe(400);

    const institution = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@university.example", password: "ValidPassword2026", name: "University Admin", role: "university", accepted_terms: true }),
    });
    expect(institution.status).toBe(400);

    const employerWithoutOrganization = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "recruiter@newco.example", password: "ValidPassword2026", name: "New Recruiter", role: "employer", accepted_terms: true }),
    });
    expect(employerWithoutOrganization.status).toBe(400);
    expect((await employerWithoutOrganization.json() as any).error).toBe("organization_name_required");
  });

  it("rate-limits bulk account creation by network without storing raw IP addresses", async () => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const response = await app.request("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Real-IP": "198.51.100.25" },
        body: JSON.stringify({}),
      });
      expect(response.status).toBe(400);
    }
    const limited = await app.request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Real-IP": "198.51.100.25" },
      body: JSON.stringify({}),
    });
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBeTruthy();
    const stored = db.prepare("SELECT key_hash FROM security_rate_limit_events WHERE action='signup' LIMIT 1").get() as any;
    expect(stored.key_hash).not.toContain("198.51.100.25");
  });

  it("lets employers post a published job and see it in their job list", async () => {
    const employer = await login(app, "recruiter@careerbridge.test", "employer");
    const create = await app.request("/api/employer/jobs", {
      method: "POST",
      headers: { Cookie: employer.cookie, "Content-Type": "application/json", "X-CSRF-Token": employer.csrf },
      body: JSON.stringify({
        title: "Operations Associate",
        location: "Remote",
        work_mode: "remote",
        employment_type: "full-time",
        compensation: "$70,000",
        description: "Run trust and operations work for a fast-growing marketplace with clear verification controls.",
        skills: "operations, SQL, communication",
        verification_requirements: ["identity_verified", "account_ownership", "income_verification", "risk_assessment"],
        status: "published",
      }),
    });

    expect(create.status).toBe(201);
    const created = await create.json() as any;
    const employerJobs = await app.request("/api/employer/jobs", { headers: { Cookie: employer.cookie } });
    expect(employerJobs.status).toBe(200);
    const owned = await employerJobs.json() as any;
    expect(owned.jobs.some((job: any) => job.id === created.id && job.status === "published")).toBe(true);
    const stored = owned.jobs.find((job: any) => job.id === created.id);
    expect(stored.verification_requirements).toEqual(["identity_verified", "account_ownership", "income_verification"]);

    const publicJobs = await app.request("/api/jobs");
    const publicBody = await publicJobs.json() as any;
    expect(publicBody.jobs.some((job: any) => job.id === created.id)).toBe(true);
  });
});

describe("PASSID HTTP client contract", () => {
  it("uses the documented sandbox paths, idempotency header, and server-side status lookup", async () => {
    const originalFetch = globalThis.fetch;
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.endsWith("/sessions") && init?.method === "POST") {
        return new Response(JSON.stringify({
          data: {
            session_id: "pcs_sandbox_contract",
            hosted_url: "https://app.passid.io/connect/authorize?session=pcs_sandbox_contract",
            status: "pending_customer",
            expires_at: "2026-07-17T18:00:00.000Z",
          },
        }), { status: 201, headers: { "Content-Type": "application/json" } });
      }
      if (url.endsWith("/keys")) {
        return Response.json({ data: { active: true, environment: "sandbox" } }, { headers: { "x-request-id": "req_key_contract" } });
      }
      if (url.endsWith("/token") && init?.method === "POST") {
        return Response.json({ data: { connection_id: "conn_sandbox_contract", institution_subject_id: "subject_contract", granted_scopes: ["identity.read"], evidence_result: "verified" } }, { headers: { "x-request-id": "req_token_contract" } });
      }
      if (url.endsWith("/sessions/pcs_sandbox_contract")) {
        return Response.json({
          data: {
            session_id: "pcs_sandbox_contract",
            status: "approved",
            connection_id: "conn_sandbox_contract",
            granted_scopes: ["identity.read"],
          },
        });
      }
      if (url.endsWith("/connections/conn_sandbox_contract/identity")) {
        return Response.json({ data: { identity: { verification_status: "verified" } } });
      }
      throw new Error(`Unexpected PASSID request: ${url}`);
    }) as typeof fetch;

    try {
      const client = createPassidClient(baseEnv);
      const readiness = await client.checkConnection();
      await client.createSession({
        scopes: ["identity.read"],
        purpose: "CareerBridge contract test",
        return_url: "https://api.careerbridge.test/api/passid/callback",
        application_reference: "app_contract",
        idempotency_key: "cbsess_contract",
        state: "state_contract",
        code_challenge: "challenge_contract",
        code_challenge_method: "S256",
      });
      const exchanged = await client.exchangeCode({
        session_id: "pcs_sandbox_contract",
        code: "code_contract",
        redirect_uri: "https://api.careerbridge.test/api/passid/callback",
        code_verifier: "verifier_contract_abcdefghijklmnopqrstuvwxyz1234567890",
        idempotency_key: "token_contract",
      });
      const result = await client.retrieveSession("pcs_sandbox_contract");

      expect(readiness).toEqual({ active: true, environment: "sandbox", request_id: "req_key_contract" });
      expect(calls[1]?.url).toBe("https://api.passid.io/api/sandbox/connect/sessions");
      expect(new Headers(calls[1]?.init?.headers).get("Idempotency-Key")).toBe("cbsess_contract");
      const requestBody = JSON.parse(String(calls[1]?.init?.body));
      expect(requestBody.access_duration).toBe("90days");
      expect(requestBody.state).toBe("state_contract");
      expect(requestBody.code_challenge).toBe("challenge_contract");
      expect(requestBody.code_challenge_method).toBe("S256");
      const tokenCall = calls.find((call) => call.url.endsWith("/token"))!;
      expect(new Headers(tokenCall.init?.headers).get("Idempotency-Key")).toBe("token_contract");
      expect(JSON.parse(String(tokenCall.init?.body))).toEqual({
        grant_type: "authorization_code",
        code: "code_contract",
        redirect_uri: "https://api.careerbridge.test/api/passid/callback",
        code_verifier: "verifier_contract_abcdefghijklmnopqrstuvwxyz1234567890",
      });
      expect(exchanged.connection_id).toBe("conn_sandbox_contract");
      expect(exchanged.institution_subject_id).toBe("subject_contract");
      expect(result.connection_id).toBe("conn_sandbox_contract");
      expect(result.verification.identity).toBe("verified");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
