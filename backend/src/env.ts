export type PassidEnvironment = "sandbox" | "live";

export interface CareerBridgeEnv {
  NODE_ENV: string;
  PORT: number;
  APP_URL: string;
  API_URL: string;
  DATABASE_URL: string;
  SESSION_SECRET: string;
  ENCRYPTION_KEY: string;
  PASSID_API_BASE_URL: string;
  PASSID_SECRET_KEY: string;
  PASSID_PUBLISHABLE_KEY: string;
  PASSID_WEBHOOK_SECRET: string;
  PASSID_ENVIRONMENT: PassidEnvironment;
  PASSID_REDIRECT_URL: string;
  PASSID_WEBHOOK_URL: string;
  PASSID_PAY_PREVIEW_ENABLED: boolean;
}

const PLACEHOLDER = /^(changeme|change-me|placeholder|secret|test|todo|example)$/i;

function read(source: Record<string, string | undefined>, name: string): string {
  return (source[name] ?? "").trim();
}

function isProd(source: Record<string, string | undefined>): boolean {
  return read(source, "NODE_ENV") === "production";
}

function requireValue(
  source: Record<string, string | undefined>,
  name: string,
  issues: string[],
  minLength = 1,
): string {
  const value = read(source, name);
  if (!value) issues.push(`${name}: missing`);
  else if (value.length < minLength) issues.push(`${name}: too short`);
  else if (PLACEHOLDER.test(value)) issues.push(`${name}: placeholder`);
  return value;
}

function requireHttpsUrl(source: Record<string, string | undefined>, name: string, issues: string[]): string {
  const value = requireValue(source, name, issues);
  if (!value) return value;
  try {
    const url = new URL(value);
    if (isProd(source) && url.protocol !== "https:") issues.push(`${name}: must use https in production`);
  } catch {
    issues.push(`${name}: invalid URL`);
  }
  return value;
}

export function getEnvironmentIssues(source: Record<string, string | undefined> = process.env): string[] {
  // PassID's current integration guide calls these PASSID_CONNECT_KEY and
  // PASSID_CONNECT_BASE. Keep the original names as backwards-compatible
  // aliases so existing Railway deployments can rotate without downtime.
  const normalized = {
    ...source,
    PASSID_API_BASE_URL: read(source, "PASSID_CONNECT_BASE") || read(source, "PASSID_API_BASE_URL"),
    PASSID_SECRET_KEY: read(source, "PASSID_CONNECT_KEY") || read(source, "PASSID_SECRET_KEY"),
  };
  const issues: string[] = [];
  const production = isProd(normalized);

  requireHttpsUrl(normalized, "APP_URL", issues);
  requireHttpsUrl(normalized, "API_URL", issues);
  requireValue(normalized, "DATABASE_URL", issues);
  requireValue(normalized, "SESSION_SECRET", issues, production ? 32 : 16);
  requireValue(normalized, "ENCRYPTION_KEY", issues, production ? 32 : 16);
  requireHttpsUrl(normalized, "PASSID_API_BASE_URL", issues);
  requireValue(normalized, "PASSID_SECRET_KEY", issues, production ? 24 : 8);
  requireValue(normalized, "PASSID_WEBHOOK_SECRET", issues, production ? 24 : 8);
  requireHttpsUrl(normalized, "PASSID_REDIRECT_URL", issues);
  requireHttpsUrl(normalized, "PASSID_WEBHOOK_URL", issues);

  const env = read(normalized, "PASSID_ENVIRONMENT");
  if (env !== "sandbox" && env !== "live") issues.push("PASSID_ENVIRONMENT: must be sandbox or live");
  const secret = read(normalized, "PASSID_SECRET_KEY");
  const publishable = read(normalized, "PASSID_PUBLISHABLE_KEY");
  if (env === "live" && (secret.startsWith("sk_test_") || publishable.startsWith("pk_test_"))) {
    issues.push("PASSID credentials: sandbox keys cannot be used in live mode");
  }
  if (env === "sandbox" && (secret.startsWith("sk_live_") || publishable.startsWith("pk_live_"))) {
    issues.push("PASSID credentials: live keys cannot be used in sandbox mode");
  }
  const apiBase = read(normalized, "PASSID_API_BASE_URL").replace(/\/+$/, "");
  if (env === "sandbox" && /\/v1\/connect$/.test(apiBase)) {
    issues.push("PASSID_API_BASE_URL: production Connect URL cannot be used in sandbox mode");
  }
  if (env === "live" && /\/api\/sandbox\/connect$/.test(apiBase)) {
    issues.push("PASSID_API_BASE_URL: sandbox Connect URL cannot be used in live mode");
  }
  return Array.from(new Set(issues));
}

export function loadEnv(source: Record<string, string | undefined> = process.env): CareerBridgeEnv {
  const issues = getEnvironmentIssues(source);
  if (issues.length && source.NODE_ENV === "production") {
    console.error("CareerBridge production configuration is invalid. Secret values were not printed.");
    for (const issue of issues) console.error(`- ${issue}`);
    throw new Error("Invalid production environment");
  }
  const passidEnvironment = (read(source, "PASSID_ENVIRONMENT") || "sandbox") as PassidEnvironment;
  return {
    NODE_ENV: read(source, "NODE_ENV") || "development",
    PORT: Number(read(source, "PORT") || 4100),
    APP_URL: read(source, "APP_URL") || "http://localhost:5174",
    API_URL: read(source, "API_URL") || "http://localhost:4100",
    DATABASE_URL: read(source, "DATABASE_URL") || "careerbridge/database/careerbridge.db",
    SESSION_SECRET: read(source, "SESSION_SECRET") || "dev_session_secret_32_bytes_minimum",
    ENCRYPTION_KEY: read(source, "ENCRYPTION_KEY") || "dev_encryption_key_32_bytes_min",
    PASSID_API_BASE_URL: read(source, "PASSID_CONNECT_BASE") || read(source, "PASSID_API_BASE_URL")
      || (passidEnvironment === "sandbox" ? "https://api.passid.io/api/sandbox/connect" : "https://api.passid.io/v1/connect"),
    PASSID_SECRET_KEY: read(source, "PASSID_CONNECT_KEY") || read(source, "PASSID_SECRET_KEY") || "sk_test_local_careerbridge",
    PASSID_PUBLISHABLE_KEY: read(source, "PASSID_PUBLISHABLE_KEY"),
    PASSID_WEBHOOK_SECRET: read(source, "PASSID_WEBHOOK_SECRET") || "whsec_test_local_careerbridge",
    PASSID_ENVIRONMENT: passidEnvironment,
    PASSID_REDIRECT_URL: read(source, "PASSID_REDIRECT_URL") || "http://localhost:4100/api/passid/callback",
    PASSID_WEBHOOK_URL: read(source, "PASSID_WEBHOOK_URL") || "http://localhost:4100/api/webhooks/passid",
    PASSID_PAY_PREVIEW_ENABLED: read(source, "PASSID_PAY_PREVIEW_ENABLED").toLowerCase() !== "false",
  };
}

export function safeVersion() {
  return {
    service: "careerbridge",
    railwayDeploymentId: process.env.RAILWAY_DEPLOYMENT_ID ?? null,
    railwayGitCommitSha: process.env.RAILWAY_GIT_COMMIT_SHA ?? null,
    railwayGitCommitMessage: process.env.RAILWAY_GIT_COMMIT_MESSAGE ?? null,
  };
}
