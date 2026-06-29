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
  const issues: string[] = [];
  const production = isProd(source);

  requireHttpsUrl(source, "APP_URL", issues);
  requireHttpsUrl(source, "API_URL", issues);
  requireValue(source, "DATABASE_URL", issues);
  requireValue(source, "SESSION_SECRET", issues, production ? 32 : 16);
  requireValue(source, "ENCRYPTION_KEY", issues, production ? 32 : 16);
  requireHttpsUrl(source, "PASSID_API_BASE_URL", issues);
  requireValue(source, "PASSID_SECRET_KEY", issues, production ? 24 : 8);
  requireValue(source, "PASSID_PUBLISHABLE_KEY", issues, production ? 12 : 8);
  requireValue(source, "PASSID_WEBHOOK_SECRET", issues, production ? 24 : 8);
  requireHttpsUrl(source, "PASSID_REDIRECT_URL", issues);
  requireHttpsUrl(source, "PASSID_WEBHOOK_URL", issues);

  const env = read(source, "PASSID_ENVIRONMENT");
  if (env !== "sandbox" && env !== "live") issues.push("PASSID_ENVIRONMENT: must be sandbox or live");
  const secret = read(source, "PASSID_SECRET_KEY");
  const publishable = read(source, "PASSID_PUBLISHABLE_KEY");
  if (env === "live" && (secret.startsWith("sk_test_") || publishable.startsWith("pk_test_"))) {
    issues.push("PASSID credentials: sandbox keys cannot be used in live mode");
  }
  if (env === "sandbox" && (secret.startsWith("sk_live_") || publishable.startsWith("pk_live_"))) {
    issues.push("PASSID credentials: live keys cannot be used in sandbox mode");
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
  return {
    NODE_ENV: read(source, "NODE_ENV") || "development",
    PORT: Number(read(source, "PORT") || 4100),
    APP_URL: read(source, "APP_URL") || "http://localhost:5174",
    API_URL: read(source, "API_URL") || "http://localhost:4100",
    DATABASE_URL: read(source, "DATABASE_URL") || "careerbridge/database/careerbridge.db",
    SESSION_SECRET: read(source, "SESSION_SECRET") || "dev_session_secret_32_bytes_minimum",
    ENCRYPTION_KEY: read(source, "ENCRYPTION_KEY") || "dev_encryption_key_32_bytes_min",
    PASSID_API_BASE_URL: read(source, "PASSID_API_BASE_URL") || "https://api.passid.io",
    PASSID_SECRET_KEY: read(source, "PASSID_SECRET_KEY") || "sk_test_local_careerbridge",
    PASSID_PUBLISHABLE_KEY: read(source, "PASSID_PUBLISHABLE_KEY") || "pk_test_local_careerbridge",
    PASSID_WEBHOOK_SECRET: read(source, "PASSID_WEBHOOK_SECRET") || "whsec_test_local_careerbridge",
    PASSID_ENVIRONMENT: (read(source, "PASSID_ENVIRONMENT") || "sandbox") as PassidEnvironment,
    PASSID_REDIRECT_URL: read(source, "PASSID_REDIRECT_URL") || "http://localhost:4100/api/passid/callback",
    PASSID_WEBHOOK_URL: read(source, "PASSID_WEBHOOK_URL") || "http://localhost:4100/api/webhooks/passid",
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
