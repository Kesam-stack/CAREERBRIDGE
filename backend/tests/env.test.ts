import { describe, expect, it } from "bun:test";
import { getEnvironmentIssues, loadEnv } from "../src/env";

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
    RESEND_API_KEY: "re_test_careerbridge_delivery",
    PASSWORD_RESET_EMAIL_FROM: "CareerBridge <security@careerbridge.example>",
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

  it("keeps the service available when optional password-reset delivery is not configured", () => {
    expect(getEnvironmentIssues({ ...complete, RESEND_API_KEY: "", PASSWORD_RESET_EMAIL_FROM: "" })).toEqual([]);
  });

  it("rejects direct password-reset testing in a live PASSID environment", () => {
    expect(getEnvironmentIssues({ ...complete, PASSWORD_RESET_TEST_MODE: "true" }))
      .toContain("PASSWORD_RESET_TEST_MODE: can only be enabled with PASSID_ENVIRONMENT=sandbox");
  });

  it("defaults direct demo password testing on only in sandbox", () => {
    const sandbox = loadEnv({
      NODE_ENV: "development",
      PASSID_ENVIRONMENT: "sandbox",
      PASSWORD_RESET_TEST_MODE: undefined,
    });
    expect(sandbox.PASSWORD_RESET_TEST_MODE).toBe(true);
    expect(loadEnv({ NODE_ENV: "development", PASSID_ENVIRONMENT: "sandbox", PASSWORD_RESET_TEST_MODE: "false" }).PASSWORD_RESET_TEST_MODE).toBe(false);
  });

  it("rejects a sandbox Connect base URL in live mode", () => {
    const issues = getEnvironmentIssues({ ...complete, PASSID_API_BASE_URL: "https://api.passid.io/api/sandbox/connect" });
    expect(issues).toContain("PASSID_API_BASE_URL: sandbox Connect URL cannot be used in live mode");
  });

  it("accepts the current PassID Connect variable names", () => {
    const source = {
      ...complete,
      PASSID_API_BASE_URL: undefined,
      PASSID_SECRET_KEY: undefined,
      PASSID_CONNECT_BASE: "https://api.passid.io/v1/connect",
      PASSID_CONNECT_KEY: "sk_live_" + "z".repeat(32),
    };
    expect(getEnvironmentIssues(source)).toEqual([]);
    const env = loadEnv(source);
    expect(env.PASSID_API_BASE_URL).toBe(source.PASSID_CONNECT_BASE);
    expect(env.PASSID_SECRET_KEY).toBe(source.PASSID_CONNECT_KEY);
  });

  it("keeps Pay environment independent from Connect and validates Pay key format", () => {
    expect(getEnvironmentIssues({ ...complete, PASSID_PAY_SECRET_KEY: "pay_test_sandbox_can_run_beside_live_connect" })).toEqual([]);
    expect(getEnvironmentIssues({ ...complete, PASSID_PAY_SECRET_KEY: "sk_live_not_a_pay_key" }))
      .toContain("PASSID_PAY_SECRET_KEY: must be a pay_test_ or pay_live_ key");
  });
});
