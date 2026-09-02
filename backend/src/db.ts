import { Database } from "bun:sqlite";
import { dirname } from "path";
import { mkdirSync } from "fs";

export type Role = "candidate" | "employer" | "university" | "admin";

export interface CareerBridgeDb {
  db: Database;
  close(): void;
}

const STORED_VERIFICATION_REQUIREMENTS = new Set([
  "identity_verified",
  "account_ownership",
  "income_verification",
]);

function jsonArray(value: unknown): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(String(value));
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

export function openCareerBridgeDb(path: string): CareerBridgeDb {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path, { create: true });
  db.run("PRAGMA journal_mode = WAL");
  db.run("PRAGMA foreign_keys = ON");
  migrate(db);
  seed(db);
  return { db, close: () => db.close() };
}

export function migrate(db: Database): void {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('candidate','employer','university','admin')),
      name TEXT NOT NULL,
      email_verified INTEGER NOT NULL DEFAULT 0,
      suspended_at INTEGER,
      created_at INTEGER NOT NULL
    )
  `);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`);
  db.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    requested_from_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
  )`);
  db.run("CREATE INDEX IF NOT EXISTS idx_password_reset_lookup ON password_reset_tokens(token_hash,expires_at,used_at)");
  // OTP login has been retired. Remove the legacy challenge table (and any
  // short-lived codes it contained) when upgrading an existing database.
  db.run(`DROP TABLE IF EXISTS auth_otps`);
  db.run(`CREATE TABLE IF NOT EXISTS candidate_profiles (user_id TEXT PRIMARY KEY REFERENCES users(id), headline TEXT, education TEXT, experience TEXT, skills TEXT, passid_status TEXT NOT NULL DEFAULT 'not_connected')`);
  db.run(`CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'employer', status TEXT NOT NULL DEFAULT 'pending', website TEXT, created_at INTEGER NOT NULL)`);
  db.run(`CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), title TEXT NOT NULL, location TEXT NOT NULL, work_mode TEXT NOT NULL, employment_type TEXT NOT NULL, compensation TEXT, description TEXT NOT NULL, qualifications TEXT, skills TEXT, deadline TEXT, verification_requirements TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', created_at INTEGER NOT NULL)`);
  db.run(`CREATE TABLE IF NOT EXISTS saved_jobs (user_id TEXT NOT NULL REFERENCES users(id), job_id TEXT NOT NULL REFERENCES jobs(id), created_at INTEGER NOT NULL, PRIMARY KEY(user_id, job_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS applications (id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), candidate_user_id TEXT NOT NULL REFERENCES users(id), status TEXT NOT NULL, cover_note TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(job_id, candidate_user_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS passid_sessions (id TEXT PRIMARY KEY, application_id TEXT NOT NULL REFERENCES applications(id), candidate_user_id TEXT NOT NULL REFERENCES users(id), state_hash TEXT NOT NULL UNIQUE, pkce_verifier_ciphertext TEXT, redirect_uri TEXT, passid_session_id TEXT, hosted_url TEXT, status TEXT NOT NULL, scopes TEXT NOT NULL, purpose TEXT NOT NULL, environment TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL)`);
  const passidSessionColumns = new Set((db.prepare("PRAGMA table_info(passid_sessions)").all() as any[]).map((column) => String(column.name)));
  if (!passidSessionColumns.has("pkce_verifier_ciphertext")) db.run("ALTER TABLE passid_sessions ADD COLUMN pkce_verifier_ciphertext TEXT");
  if (!passidSessionColumns.has("redirect_uri")) db.run("ALTER TABLE passid_sessions ADD COLUMN redirect_uri TEXT");
  db.run(`CREATE TABLE IF NOT EXISTS passid_connections (id TEXT PRIMARY KEY, application_id TEXT NOT NULL REFERENCES applications(id), candidate_user_id TEXT NOT NULL REFERENCES users(id), passid_session_id TEXT NOT NULL, connection_id TEXT, status TEXT NOT NULL, granted_scopes TEXT NOT NULL, consent_status TEXT NOT NULL, expires_at INTEGER, last_webhook_event TEXT, last_api_request_id TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`);
  const passidConnectionColumns = new Set((db.prepare("PRAGMA table_info(passid_connections)").all() as any[]).map((column) => String(column.name)));
  if (!passidConnectionColumns.has("institution_subject_hash")) db.run("ALTER TABLE passid_connections ADD COLUMN institution_subject_hash TEXT");
  db.run(`CREATE TABLE IF NOT EXISTS passid_subject_bindings (
    subject_hash TEXT PRIMARY KEY,
    candidate_user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
    first_connection_id TEXT,
    status TEXT NOT NULL DEFAULT 'bound',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS security_rate_limit_events (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  db.run("CREATE INDEX IF NOT EXISTS idx_security_rate_limit_lookup ON security_rate_limit_events(action,key_hash,created_at)");
  db.run(`CREATE TABLE IF NOT EXISTS verification_results (id TEXT PRIMARY KEY, application_id TEXT NOT NULL REFERENCES applications(id), candidate_user_id TEXT NOT NULL REFERENCES users(id), result_json TEXT NOT NULL, updated_at INTEGER NOT NULL)`);
  db.run(`CREATE TABLE IF NOT EXISTS passid_webhook_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, passid_connection_id TEXT, processed_at INTEGER NOT NULL, payload_summary TEXT NOT NULL)`);
  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, actor_user_id TEXT, action TEXT NOT NULL, target_type TEXT, target_id TEXT, detail_json TEXT NOT NULL, created_at INTEGER NOT NULL)`);
  // Mirrors PassID Pay payment intents (https://passid.io/integration-guide#guide-pay);
  // passid_intent_id is the real /v1/pay/payment-intents id, not a local simulation.
  db.run(`CREATE TABLE IF NOT EXISTS pay_payment_intents (
    id TEXT PRIMARY KEY,
    passid_intent_id TEXT NOT NULL UNIQUE,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    application_id TEXT NOT NULL REFERENCES applications(id),
    candidate_user_id TEXT NOT NULL REFERENCES users(id),
    created_by_user_id TEXT NOT NULL REFERENCES users(id),
    amount_minor INTEGER NOT NULL CHECK(amount_minor > 0 AND amount_minor <= 100000000),
    currency TEXT NOT NULL CHECK(currency='USD'),
    purpose TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('requires_consent','ready_to_execute','consent_declined','simulated_completed','failed')),
    hosted_url TEXT,
    credential_id TEXT,
    idempotency_key TEXT NOT NULL,
    consented_at INTEGER,
    executed_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(organization_id,idempotency_key)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS pay_payment_events (
    id TEXT PRIMARY KEY,
    payment_intent_id TEXT NOT NULL REFERENCES pay_payment_intents(id),
    type TEXT NOT NULL,
    actor_user_id TEXT,
    payload_summary TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  db.run("CREATE INDEX IF NOT EXISTS idx_pay_payment_intents_application ON pay_payment_intents(application_id,created_at)");
  db.run("CREATE INDEX IF NOT EXISTS idx_pay_payment_events_intent ON pay_payment_events(payment_intent_id,created_at)");

  for (const job of db.prepare("SELECT id, verification_requirements FROM jobs").all() as any[]) {
    const requirements = jsonArray(job.verification_requirements).filter((req) => STORED_VERIFICATION_REQUIREMENTS.has(req));
    const next = job.id === "job_demo" && !requirements.includes("income_verification") ? [...requirements, "income_verification"] : requirements;
    if (JSON.stringify(next) !== String(job.verification_requirements)) {
      db.prepare("UPDATE jobs SET verification_requirements=? WHERE id=?").run(JSON.stringify(next), job.id);
    }
  }
}

export function seed(db: Database): void {
  const existing = db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").get();
  if (existing) return;
  const now = Date.now();
  db.prepare("INSERT INTO users (id,email,password_hash,role,name,email_verified,created_at) VALUES ('admin_demo','admin@careerbridge.test','pbkdf2$demo$demo','admin','CareerBridge Admin',1,?)").run(now);
  db.prepare("INSERT INTO users (id,email,password_hash,role,name,email_verified,created_at) VALUES ('candidate_demo','amara@careerbridge.test','pbkdf2$demo$demo','candidate','Amara Osei',1,?)").run(now);
  db.prepare("INSERT INTO candidate_profiles (user_id,headline,education,experience,skills) VALUES ('candidate_demo','Computer science graduate','University of Nairobi — BSc Computer Science','Campus ambassador, software intern','React, SQL, payments, compliance')").run();
  db.prepare("INSERT INTO users (id,email,password_hash,role,name,email_verified,created_at) VALUES ('employer_demo','recruiter@careerbridge.test','pbkdf2$demo$demo','employer','Maya Patel',1,?)").run(now);
  db.prepare("INSERT INTO organizations (id,owner_user_id,name,type,status,website,created_at) VALUES ('org_demo','employer_demo','Northstar Fintech','employer','approved','https://northstar.example',?)").run(now);
  db.prepare(`
    INSERT INTO jobs (id,organization_id,title,location,work_mode,employment_type,compensation,description,qualifications,skills,deadline,verification_requirements,status,created_at)
    VALUES ('job_demo','org_demo','Product Operations Internship','New York, NY','hybrid','internship','$28/hour','Support marketplace launch operations, partner onboarding, and trust operations.','Student or recent graduate with strong writing and analysis skills.','operations, fintech, SQL, customer research','2026-08-15',?,'published',?)
  `).run(JSON.stringify(["identity_verified", "income_verification"]), now);
}
