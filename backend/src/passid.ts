import type { CareerBridgeEnv } from "./env";
import { redactError } from "./security";

export interface CreatePassidSessionInput {
  scopes: string[];
  purpose: string;
  return_url: string;
  application_reference: string;
  state: string;
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
  createSession(input: CreatePassidSessionInput): Promise<PassidSession>;
  retrieveSession(sessionId: string): Promise<PassidConnectionResult>;
  revokeConnection(connectionId: string): Promise<{ status: string }>;
}

function normalizeBody(body: any): any {
  return body?.data ?? body;
}

export function createPassidClient(env: CareerBridgeEnv): PassidClient {
  const base = env.PASSID_API_BASE_URL.replace(/\/+$/, "");
  async function request(path: string, init: RequestInit = {}) {
    const response = await fetch(`${base}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${env.PASSID_SECRET_KEY}`,
        "Content-Type": "application/json",
        ...(init.headers ?? {}),
      },
    });
    const requestId = response.headers.get("x-request-id") ?? undefined;
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const err = new Error(`PASSID_API_${response.status}`);
      (err as any).requestId = requestId;
      throw err;
    }
    return { body: normalizeBody(body), requestId };
  }

  return {
    async createSession(input) {
      try {
        const { body } = await request("/v1/connect/sessions", {
          method: "POST",
          body: JSON.stringify({
            scopes: input.scopes,
            purpose: input.purpose,
            return_url: input.return_url,
            application_reference: input.application_reference,
            state: input.state,
            environment: env.PASSID_ENVIRONMENT,
          }),
        });
        return {
          session_id: body.session_id,
          hosted_url: body.hosted_url,
          status: body.status ?? "pending_customer",
          expires_at: body.expires_at,
        };
      } catch (error) {
        throw new Error(`PASSID_SESSION_CREATE_FAILED:${redactError(error)}`);
      }
    },
    async retrieveSession(sessionId) {
      try {
        const { body, requestId } = await request(`/v1/connect/sessions/${encodeURIComponent(sessionId)}`);
        return {
          session_id: body.session_id ?? sessionId,
          status: body.status ?? "pending",
          connection_id: body.connection_id,
          granted_scopes: Array.isArray(body.granted_scopes) ? body.granted_scopes : [],
          verification: body.verification ?? {},
          expires_at: body.expires_at,
          request_id: requestId,
        };
      } catch (error) {
        throw new Error(`PASSID_SESSION_RETRIEVE_FAILED:${redactError(error)}`);
      }
    },
    async revokeConnection(connectionId) {
      try {
        const { body } = await request(`/v1/connect/connections/${encodeURIComponent(connectionId)}/revoke`, { method: "POST" });
        return { status: body.status ?? "revoked" };
      } catch (error) {
        throw new Error(`PASSID_REVOKE_FAILED:${redactError(error)}`);
      }
    },
  };
}
