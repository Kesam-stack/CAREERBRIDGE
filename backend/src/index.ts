import { serve } from "bun";
import { createCareerBridgeApp } from "./app";
import { loadEnv } from "./env";

const env = loadEnv();
console.log("[startup] PASSID config:", {
  environment: env.PASSID_ENVIRONMENT,
  baseUrl: env.PASSID_API_BASE_URL,
  secretKeyConfigured: Boolean(env.PASSID_SECRET_KEY),
  webhookSecretConfigured: Boolean(env.PASSID_WEBHOOK_SECRET),
  passwordResetEmailConfigured: Boolean(env.RESEND_API_KEY && env.PASSWORD_RESET_EMAIL_FROM),
  passwordResetTestMode: env.PASSWORD_RESET_TEST_MODE && env.PASSID_ENVIRONMENT === "sandbox",
});
const { app } = createCareerBridgeApp({ env });

serve({
  port: env.PORT,
  fetch: app.fetch,
});

console.log(`CareerBridge API listening on ${env.PORT}`);
