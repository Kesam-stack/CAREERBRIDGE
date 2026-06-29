import { describe, expect, it } from "bun:test";
import { getEnvironmentIssues } from "../src/env";

describe("CareerBridge production environment validation", () => {
  const complete = {
    NODE_ENV: "production",
    APP_URL: "https://careerbridge.example",
    API_URL: "https://api.careerbridge.example",
    DATABASE_URL: "/data/careerbridge.db",
    SESSION_SECRET: "s".repeat(40),
    ENCRYPTION_KEY: "e".repeat(40),
    PASSID_API_BASE_URL: "https://api.passid.io",
    PASSID_SECRET_KEY: "sk_live_" + "a".repeat(32),
    PASSID_PUBLISHABLE_KEY: "pk_live_" + "b".repeat(24),
    PASSID_WEBHOOK_SECRET: "whsec_" + "c".repeat(32),
    PASSID_ENVIRONMENT: "live",
    PASSID_REDIRECT_URL: "https://api.careerbridge.example/api/passid/callback",
    PASSID_WEBHOOK_URL: "https://api.careerbridge.example/api/webhooks/passid",
  };

  it("accepts complete live configuration without exposing values", () => {
    expect(getEnvironmentIssues(complete)).toEqual([]);
  });

  it("blocks sandbox keys in live mode", () => {
    const issues = getEnvironmentIssues({ ...complete, PASSID_SECRET_KEY: "sk_test_wrong_environment" });
    expect(issues.join(" ")).toContain("sandbox keys cannot be used in live mode");
    expect(issues.join(" ")).not.toContain("sk_test_wrong_environment");
  });

  it("requires HTTPS URLs in production", () => {
    const issues = getEnvironmentIssues({ ...complete, APP_URL: "http://careerbridge.example" });
    expect(issues).toContain("APP_URL: must use https in production");
  });
});
