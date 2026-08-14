import type { CareerBridgeEnv } from "./env";
import { redactError } from "./security";

// Limit concurrent Passid API calls to prevent rate limiting under load.
class Semaphore {
  private queue: Array<() => void> = [];
  private running = 0;
  constructor(private readonly concurrency: number) {}
  acquire(): Promise<void> {
    if (this.running < this.concurrency) {
      this.running++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.queue.push(() => { this.running++; resolve(); });
    });
  }
  release(): void {
    this.running--;
    const next = this.queue.shift();
    if (next) next();
  }
}

const passidSemaphore = new Semaphore(2);

export interface CreatePassidSessionInput {
  scopes: string[];
  purpose: string;
  return_url: string;
  application_reference: string;
  idempotency_key: string;
  access_duration?: "90days" | "1year" | "permanent";
}

export interface PassidSession {
  session_id: string;
  hosted_url: string;
  status: string;
  expires_at?: string;
}

export interface PassidConnectionResult {
  session_id: string;
  status: string;
  connection_id?: string;
  granted_scopes: string[];
  verification: Record<string, string>;
  expires_at?: string;
  request_id?: string;
}

export interface PassidClient {
  checkConnection(): Promise<{ active: boolean; environment?: string; request_id?: string }>;
  createSession(input: CreatePassidSessionInput): Promise<PassidSession>;
  retrieveSession(sessionId: string): Promise<PassidConnectionResult>;
  revokeConnection(connectionId: string): Promise<{ status: string }>;
}

function normalizeBody(body: any): any {
  return body?.data ?? body;
}

export function createPassidClient(env: CareerBridgeEnv): PassidClient {
  const configuredBase = env.PASSID_API_BASE_URL.replace(/\/+$/, "");
  const base = /\/(?:v1|api\/sandbox)\/connect$/.test(configuredBase)
    ? configuredBase
    : `${configuredBase}${env.PASSID_ENVIRONMENT === "sandbox" ? "/api/sandbox/connect" : "/v1/connect"}`;
  const MAX_RETRIES = 3;

  function backoffMs(attempt: number, retryAfterSeconds?: number): number {
    if (retryAfterSeconds != null && Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
      return retryAfterSeconds * 1000;
    }
    // Exponential backoff: 500ms * 2^attempt, capped at 30s, with ±25% jitter
    const base = Math.min(30_000, 500 * Math.pow(2, attempt));
    const jitter = base * 0.25 * (Math.random() * 2 - 1);
    return Math.max(100, Math.round(base + jitter));
  }

  async function request(path: string, init: RequestInit = {}, attempt = 0): Promise<{ body: any; requestId?: string }> {
    await passidSemaphore.acquire();
    let response: Response;
    try {
      response = await fetch(`${base}${path}`, {
        ...init,
        headers: {
          Authorization: `Bearer ${env.PASSID_SECRET_KEY}`,
          "Content-Type": "application/json",
          ...(init.headers ?? {}),
        },
      });
    } finally {
      passidSemaphore.release();
    }
    const requestId = response.headers.get("x-request-id") ?? undefined;
    const body = await response.json().catch(() => ({}));
    if (response.status === 429 && attempt < MAX_RETRIES) {
      const retryAfterHeader = response.headers.get("retry-after");
      const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : undefined;
      const delayMs = backoffMs(attempt, retryAfterSeconds);
      console.warn(`[passid] rate limited, retrying in ${delayMs}ms`, { path, attempt, requestId, retryAfterSeconds });
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return request(path, init, attempt + 1);
    }
    if (!response.ok) {
      const detail = body?.error ?? body?.message ?? body?.detail ?? body?.errors ?? "unknown_error";
      const retryAfterHeader = response.headers.get("retry-after");
      const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : undefined;
      console.error("[passid error response]", {
        path,
        status: response.status,
        requestId,
        errorCode: body?.error?.code,
      });
      const err = new Error(`PASSID_API_${response.status}:${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
      (err as any).requestId = requestId;
      (err as any).status = response.status;
      (err as any).body = body;
      (err as any).retryAfterSeconds = Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : undefined;
      throw err;
    }
    return { body: normalizeBody(body), requestId };
  }

  return {
    async checkConnection() {
      const { body, requestId } = await request("/keys");
      return {
        active: body?.active !== false,
        environment: body?.environment ? String(body.environment) : undefined,
        request_id: requestId,
      };
    },
    async createSession(input) {
      try {
        const { body } = await request("/sessions", {
          method: "POST",
          headers: { "Idempotency-Key": input.idempotency_key },
          body: JSON.stringify({
            scopes: input.scopes,
            purpose: input.purpose,
            return_url: input.return_url,
            application_reference: input.application_reference,
            access_duration: input.access_duration ?? "90days",
          }),
        });
        if (!body?.session_id || !body?.hosted_url) throw new Error("PASSID_INVALID_SESSION_RESPONSE");
        return {
          session_id: body.session_id,
          hosted_url: body.hosted_url,
          status: body.status ?? "pending_customer",
          expires_at: body.expires_at,
        };
      } catch (error) {
        const wrapped = new Error(`PASSID_SESSION_CREATE_FAILED:${redactError(error)}`);
        (wrapped as any).status = (error as any)?.status;
        (wrapped as any).requestId = (error as any)?.requestId;
        (wrapped as any).body = (error as any)?.body;
        (wrapped as any).retryAfterSeconds = (error as any)?.retryAfterSeconds;
        throw wrapped;
      }
    },
    async retrieveSession(sessionId) {
      try {
        const { body, requestId } = await request(`/sessions/${encodeURIComponent(sessionId)}`);
        const grantedScopes = Array.isArray(body.granted_scopes) ? body.granted_scopes.map(String) : [];
        const verification: Record<string, string> = {};

        if (body.status === "approved" && body.connection_id) {
          const connectionId = encodeURIComponent(String(body.connection_id));
          const endpointForScope: Record<string, { path: string; key: string; objectKey?: string }> = {
            "identity.read": { path: "identity", key: "identity", objectKey: "identity" },
            "income.read": { path: "income", key: "income", objectKey: "income" },
            "accounts.read": { path: "accounts", key: "account_ownership", objectKey: "accounts" },
            "verification_status.read": { path: "verification-status", key: "verification_status" },
          };

          await Promise.all(grantedScopes.map(async (scope: string) => {
            const endpoint = endpointForScope[scope];
            if (!endpoint) return;
            try {
              const { body: endpointBody } = await request(`/connections/${connectionId}/${endpoint.path}`);
              const value = endpoint.objectKey ? endpointBody?.[endpoint.objectKey] : endpointBody;
              const explicitStatus = value?.verification_status ?? value?.status ?? endpointBody?.verification_status ?? endpointBody?.status;
              const explicitVerified = value?.verified ?? endpointBody?.verified;
              verification[endpoint.key] = typeof explicitStatus === "string"
                ? explicitStatus
                : typeof explicitVerified === "boolean"
                  ? (explicitVerified ? "verified" : "not_verified")
                  : "available";
            } catch (error) {
              console.warn("[passid data endpoint unavailable]", {
                scope,
                status: (error as any)?.status,
                requestId: (error as any)?.requestId,
              });
              verification[endpoint.key] = "unavailable";
            }
          }));
        }

        return {
          session_id: body.session_id ?? sessionId,
          status: body.status ?? "pending",
          connection_id: body.connection_id,
          granted_scopes: grantedScopes,
          verification,
          expires_at: body.expires_at,
          request_id: requestId,
        };
      } catch (error) {
        const wrapped = new Error(`PASSID_SESSION_RETRIEVE_FAILED:${redactError(error)}`);
        (wrapped as any).status = (error as any)?.status;
        (wrapped as any).requestId = (error as any)?.requestId;
        (wrapped as any).body = (error as any)?.body;
        (wrapped as any).retryAfterSeconds = (error as any)?.retryAfterSeconds;
        throw wrapped;
      }
    },
    async revokeConnection(connectionId) {
      try {
        const { body } = await request(`/connections/${encodeURIComponent(connectionId)}/revoke`, { method: "POST" });
        return { status: body.status ?? "revoked" };
      } catch (error) {
        const wrapped = new Error(`PASSID_REVOKE_FAILED:${redactError(error)}`);
        (wrapped as any).status = (error as any)?.status;
        (wrapped as any).requestId = (error as any)?.requestId;
        (wrapped as any).body = (error as any)?.body;
        (wrapped as any).retryAfterSeconds = (error as any)?.retryAfterSeconds;
        throw wrapped;
      }
    },
  };
}
