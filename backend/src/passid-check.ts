import { loadEnv } from "./env";
import { createPassidClient } from "./passid";

const env = loadEnv();

try {
  const result = await createPassidClient(env).checkConnection();
  if (!result.active) throw new Error("Connect key is inactive");
  console.log(JSON.stringify({
    ok: true,
    environment: result.environment ?? env.PASSID_ENVIRONMENT,
    request_id: result.request_id ?? null,
  }));
} catch (error) {
  console.error(JSON.stringify({
    ok: false,
    environment: env.PASSID_ENVIRONMENT,
    status: (error as any)?.status ?? null,
    request_id: (error as any)?.requestId ?? null,
    error: (error as any)?.status === 401 ? "invalid_or_inactive_connect_key" : "passid_connection_check_failed",
  }));
  process.exit(1);
}
