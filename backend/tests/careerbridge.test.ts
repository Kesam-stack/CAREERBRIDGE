import { beforeEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { createCareerBridgeApp } from "../src/app";
import { migrate, seed } from "../src/db";
import type { CareerBridgeEnv } from "../src/env";
import { hmac } from "../src/security";
import { createPassidClient, type PassidClient } from "../src/passid";

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

  it("accepts webhook timestamps sent in seconds", async () => {
    db.prepare("INSERT INTO applications (id,job_id,candidate_user_id,status,created_at,updated_at) VALUES ('app_webhook_seconds','job_demo','candidate_demo','under_review',?,?)").run(Date.now(), Date.now());
    db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,created_at,updated_at) VALUES ('cbconn_seconds','app_webhook_seconds','candidate_demo','pcs_1','conn_sandbox_test_123','approved','[\"identity.read\"]','active',?,?)").run(Date.now(), Date.now());
    const payload = JSON.stringify({ id: "evt_seconds", type: "connection.revoked", data: { connection_id: "conn_sandbox_test_123", status: "revoked" } });
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = hmac(`${ts}.${payload}`, baseEnv.PASSID_WEBHOOK_SECRET);
    const res = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "PassID-Timestamp": ts, "PassID-Signature": `sha256=${sig}` },
      body: payload,
    });
    expect(res.status).toBe(200);
  });

  it("accepts webhook signatures with whitespace around the prefix", async () => {
    db.prepare("INSERT INTO applications (id,job_id,candidate_user_id,status,created_at,updated_at) VALUES ('app_webhook_whitespace','job_demo','candidate_demo','under_review',?,?)").run(Date.now(), Date.now());
    db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,created_at,updated_at) VALUES ('cbconn_whitespace','app_webhook_whitespace','candidate_demo','pcs_1','conn_sandbox_test_123','approved','[\"identity.read\"]','active',?,?)").run(Date.now(), Date.now());
    const payload = JSON.stringify({ id: "evt_whitespace", type: "connection.revoked", data: { connection_id: "conn_sandbox_test_123", status: "revoked" } });
    const ts = String(Date.now());
    const sig = hmac(`${ts}.${payload}`, baseEnv.PASSID_WEBHOOK_SECRET);
    const res = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "PassID-Timestamp": ts, "PassID-Signature": `sha256 = ${sig}` },
      body: payload,
    });
    expect(res.status).toBe(200);
  });

  it("accepts base64-encoded webhook signatures", async () => {
    db.prepare("INSERT INTO applications (id,job_id,candidate_user_id,status,created_at,updated_at) VALUES ('app_webhook_base64','job_demo','candidate_demo','under_review',?,?)").run(Date.now(), Date.now());
    db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,created_at,updated_at) VALUES ('cbconn_base64','app_webhook_base64','candidate_demo','pcs_1','conn_sandbox_test_123','approved','[\"identity.read\"]','active',?,?)").run(Date.now(), Date.now());
    const payload = JSON.stringify({ id: "evt_base64", type: "connection.revoked", data: { connection_id: "conn_sandbox_test_123", status: "revoked" } });
    const ts = String(Date.now());
    const sig = hmac(`${ts}.${payload}`, baseEnv.PASSID_WEBHOOK_SECRET);
    const base64Sig = Buffer.from(sig, "hex").toString("base64");
    const res = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "PassID-Timestamp": ts, "PassID-Signature": `sha256=${base64Sig}` },
      body: payload,
    });
    expect(res.status).toBe(200);
  });

  it("accepts newline-delimited webhook signatures", async () => {
    db.prepare("INSERT INTO applications (id,job_id,candidate_user_id,status,created_at,updated_at) VALUES ('app_webhook_newline','job_demo','candidate_demo','under_review',?,?)").run(Date.now(), Date.now());
    db.prepare("INSERT INTO passid_connections (id,application_id,candidate_user_id,passid_session_id,connection_id,status,granted_scopes,consent_status,created_at,updated_at) VALUES ('cbconn_newline','app_webhook_newline','candidate_demo','pcs_1','conn_sandbox_test_123','approved','[\"identity.read\"]','active',?,?)").run(Date.now(), Date.now());
    const payload = JSON.stringify({ id: "evt_newline", type: "connection.revoked", data: { connection_id: "conn_sandbox_test_123", status: "revoked" } });
    const ts = String(Date.now());
    const sig = hmac(`${ts}\n${payload}`, baseEnv.PASSID_WEBHOOK_SECRET);
    const res = await app.request("/api/webhooks/passid", {
      method: "POST",
      headers: { "Content-Type": "application/json", "PassID-Timestamp": ts, "PassID-Signature": `sha256=${sig}` },
      body: payload,
    });
    expect(res.status).toBe(200);
  });

  it("retries PASSID session creation when the provider returns a retry-after response", async () => {
    const originalFetch = globalThis.fetch;
    const responses = [
      new Response(JSON.stringify({ error: "rate_limited" }), { status: 429, headers: { "retry-after": "2", "x-request-id": "req-429-1" } }),
      new Response(JSON.stringify({ error: "rate_limited" }), { status: 429, headers: { "retry-after": "2", "x-request-id": "req-429-2" } }),
      new Response(JSON.stringify({ error: "rate_limited" }), { status: 429, headers: { "retry-after": "2", "x-request-id": "req-429-3" } }),
      new Response(JSON.stringify({ session_id: "pcs_retry", hosted_url: "https://passid.io/connect/authorize?env=sandbox&session=pcs_retry", status: "pending_customer" }), { status: 200, headers: { "x-request-id": "req-success" } }),
    ];
    let calls = 0;
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
      calls += 1;
      return Promise.resolve(responses.shift() ?? new Response(JSON.stringify({ error: "unexpected" }), { status: 500 }));
    }) as typeof fetch;

    try {
      const client = createPassidClient({ ...baseEnv, PASSID_API_BASE_URL: "https://api.passid.test" });
      const created = await client.createSession({
        scopes: ["identity.read"],
        purpose: "retry test",
        return_url: "https://careerbridge.test/callback",
        application_reference: "app_1",
        state: "state_123",
      });
      expect(created.session_id).toBe("pcs_retry");
      expect(calls).toBe(4);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("returns the underlying PASSID session creation error", async () => {
    const auth = await login(app, "amara@careerbridge.test");
    const application = await applyToDemoJob(app, auth);
    const failingApp = createCareerBridgeApp({
      env: baseEnv,
      db,
      passidClient: {
        async createSession() { throw new Error("PASSID_API_401: invalid credentials"); },
        async retrieveSession() { throw new Error("not implemented"); },
        async revokeConnection() { throw new Error("not implemented"); },
      },
    });
    const res = await failingApp.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });
    expect(res.status).toBe(502);
    const body = await res.json() as any;
    expect(body.error).toBe("passid_session_failed");
    expect(body.detail).toContain("invalid credentials");
  });

  it("blocks overlapping PASSID session creation attempts for the same application", async () => {
    const auth = await login(app, "amara@careerbridge.test");
    const application = await applyToDemoJob(app, auth);

    let releaseCreateSession: (() => void) | undefined;
    const firstCreateStarted = new Promise<void>((resolve) => {
      releaseCreateSession = resolve;
    });
    let createCalls = 0;
    const concurrentApp = createCareerBridgeApp({
      env: baseEnv,
      db,
      passidClient: {
        async createSession() {
          createCalls += 1;
          if (createCalls === 1) {
            firstCreateStarted;
            await new Promise<void>((resolve) => {
              const current = releaseCreateSession;
              if (current) {
                current();
              }
              resolve();
            });
          }
          return {
            session_id: "pcs_sandbox_test_456",
            hosted_url: "https://passid.io/connect/authorize?env=sandbox&session=pcs_sandbox_test_456",
            status: "pending_customer",
            expires_at: new Date(Date.now() + 900_000).toISOString(),
          };
        },
        async retrieveSession() { throw new Error("not implemented"); },
        async revokeConnection() { throw new Error("not implemented"); },
      },
    });

    const firstRequestPromise = concurrentApp.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });

    await Promise.resolve();
    const secondRes = await concurrentApp.app.request("/api/passid/connect/sessions", {
      method: "POST",
      headers: { Cookie: auth.cookie, "Content-Type": "application/json", "X-CSRF-Token": auth.csrf },
      body: JSON.stringify({ application_id: application.id }),
    });

    const firstRes = await firstRequestPromise;

    expect(firstRes.status).toBe(200);
    expect(secondRes.status).toBe(409);
    const body = await secondRes.json() as any;
    expect(body.error).toBe("session_creation_in_progress");
    expect(createCalls).toBe(1);
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
