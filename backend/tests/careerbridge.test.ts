import { beforeEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { createCareerBridgeApp } from "../src/app";
import { migrate, seed } from "../src/db";
import type { CareerBridgeEnv } from "../src/env";
import { hmac, randomId } from "../src/security";
import type { PassidClient } from "../src/passid";

const baseEnv: CareerBridgeEnv = {
  NODE_ENV: "test",
  PORT: 4100,
  APP_URL: "https://careerbridge.test",
  API_URL: "https://api.careerbridge.test",
  DATABASE_URL: ":memory:",
  SESSION_SECRET: "test_session_secret_32_bytes_long",
  ENCRYPTION_KEY: "test_encryption_key_32_bytes_long",
  PASSID_API_BASE_URL: "https://api.passid.io",
  PASSID_SECRET_KEY: "sk_test_careerbridge_safe_test_key",
  PASSID_PUBLISHABLE_KEY: "pk_test_careerbridge",
  PASSID_WEBHOOK_SECRET: "whsec_test_careerbridge_very_secret",
  PASSID_ENVIRONMENT: "sandbox",
  PASSID_REDIRECT_URL: "https://api.careerbridge.test/api/passid/callback",
  PASSID_WEBHOOK_URL: "https://api.careerbridge.test/api/webhooks/passid",
};

function mockPassid(): PassidClient {
  return {
    async createSession(input) {
      expect(input.scopes).toContain("identity.read");
      expect(input.return_url).toContain("state=");
      return {
        session_id: "pcs_sandbox_test_123",
        hosted_url: "https://passid.io/connect/authorize?env=sandbox&session=pcs_sandbox_test_123",
        status: "pending_customer",
        expires_at: new Date(Date.now() + 900_000).toISOString(),
      };
    },
    async retrieveSession(sessionId) {
      return {
        session_id: sessionId,
        status: "approved",
        connection_id: "conn_sandbox_test_123",
        granted_scopes: ["identity.read", "education.read", "marketplace_uniqueness.read"],
        verification: { identity: "verified", education: "verified", marketplace_uniqueness: "verified" },
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
    async createSession() {
      const err = new Error("PASSID_SESSION_CREATE_FAILED:PASSID_API_429:status=429:retry_after=60s");
      (err as any).status = 429;
      (err as any).code = "PASSID_API_429";
      (err as any).retryAfterSeconds = 60;
      (err as any).requestId = "req_passid_rate_limited";
      throw err;
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
  });

  it("allows candidates to apply and creates a server-side PASSID session without leaking secrets", async () => {
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
    expect(parsed.education).toBe("verified");
    expect(JSON.stringify(parsed)).not.toContain("bank");

    const reused = await app.request(`/api/passid/callback?state=${state}`, { redirect: "manual" });
    expect(reused.headers.get("location")).toContain("invalid_state");
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
      body: JSON.stringify({ email: "other@careerbridge.test", password: "A-valid-password-2026", name: "Other Recruiter", role: "employer" }),
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
    const payload = JSON.stringify({ id: "evt_1", type: "connection.revoked", data: { connection_id: "conn_sandbox_test_123", status: "revoked" } });
    const ts = String(Date.now());
    const sig = hmac(`${ts}.${payload}`, baseEnv.PASSID_WEBHOOK_SECRET);
    const res = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "PassID-Timestamp": ts, "PassID-Signature": `sha256=${sig}` },
      body: payload,
    });
    expect(res.status).toBe(200);
    const conn = db.prepare("SELECT consent_status FROM passid_connections WHERE id='cbconn_1'").get() as any;
    expect(conn.consent_status).toBe("revoked");
    const replay = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "PassID-Timestamp": ts, "PassID-Signature": `sha256=${sig}` },
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
  });
});
