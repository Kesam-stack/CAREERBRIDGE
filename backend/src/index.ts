import { serve } from "bun";
import { createCareerBridgeApp } from "./app";
import { loadEnv } from "./env";

const env = loadEnv();
const { app } = createCareerBridgeApp({ env });

serve({
  port: env.PORT,
  fetch: app.fetch,
});

console.log(`CareerBridge API listening on ${env.PORT}`);
