import { serve } from "bun";
import { createCareerBridgeApp } from "./app";
import { loadEnv } from "./env";

const env = loadEnv();
console.log("[startup] PASSID config:", {
  environment: env.PASSID_ENVIRONMENT,
  baseUrl: env.PASSID_API_BASE_URL,
  secretKeyStart: env.PASSID_SECRET_KEY.substring(0, 20),
  publishableKeyStart: env.PASSID_PUBLISHABLE_KEY.substring(0, 20),
});
const { app } = createCareerBridgeApp({ env });

serve({
  port: env.PORT,
  fetch: app.fetch,
});

console.log(`CareerBridge API listening on ${env.PORT}`);
