import type { CareerBridgeEnv } from "./env";
import { redactError } from "./security";

// PassID Pay (https://passid.io/integration-guide#guide-pay): one public /v1/pay API,
// environment is selected by the key (pay_test_ vs pay_live_). Execution is always
// simulated ("simulated_completed") until PassID approves licensed settlement rails.
export interface CreatePaymentIntentInput {
  amount: number;
  currency: "USD";
  purpose: string;
  idempotency_key: string;
}

export interface PaymentIntent {
  id: string;
  hosted_url?: string;
  status: string;
  amount?: number;
  currency?: string;
  purpose?: string;
  credential_id?: string;
  request_id?: string;
}

export interface PassidPayClient {
  createPaymentIntent(input: CreatePaymentIntentInput): Promise<PaymentIntent>;
  retrievePaymentIntent(id: string): Promise<PaymentIntent>;
  merchantAuthorize(id: string): Promise<PaymentIntent>;
  consent(id: string, input: { approved: boolean; confirm_destination: boolean }): Promise<PaymentIntent>;
  confirmDestination(id: string): Promise<PaymentIntent>;
  execute(id: string): Promise<PaymentIntent>;
  listEvents(id: string): Promise<Array<Record<string, unknown>>>;
  verifyCredential(id: string): Promise<{ verified: boolean; status?: string }>;
  getCredentialStatus(id: string): Promise<{ status: string }>;
}

function normalizeBody(body: any): any {
  return body?.data ?? body;
}

export function createPassidPayClient(env: CareerBridgeEnv): PassidPayClient {
  const base = env.PASSID_PAY_API_BASE_URL.replace(/\/+$/, "");
  const MAX_RETRIES = 3;

  function backoffMs(attempt: number, retryAfterSeconds?: number): number {
    if (retryAfterSeconds != null && Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
      return retryAfterSeconds * 1000;
    }
    const base = Math.min(30_000, 500 * Math.pow(2, attempt));
    const jitter = base * 0.25 * (Math.random() * 2 - 1);
    return Math.max(100, Math.round(base + jitter));
  }

  async function request(path: string, init: RequestInit = {}, attempt = 0): Promise<{ body: any; requestId?: string }> {
    const response = await fetch(`${base}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${env.PASSID_PAY_SECRET_KEY}`,
        "Content-Type": "application/json",
        ...(init.headers ?? {}),
      },
    });
    const requestId = response.headers.get("x-request-id") ?? undefined;
    const body = await response.json().catch(() => ({}));
    if (response.status === 429 && attempt < MAX_RETRIES) {
      const retryAfterHeader = response.headers.get("retry-after");
      const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : undefined;
      const delayMs = backoffMs(attempt, retryAfterSeconds);
      console.warn(`[passid-pay] rate limited, retrying in ${delayMs}ms`, { path, attempt, requestId, retryAfterSeconds });
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return request(path, init, attempt + 1);
    }
    if (!response.ok) {
      const detail = body?.error ?? body?.message ?? body?.detail ?? body?.errors ?? "unknown_error";
      console.error("[passid-pay error response]", { path, status: response.status, requestId, errorCode: body?.error?.code });
      const err = new Error(`PASSID_PAY_API_${response.status}:${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
      (err as any).requestId = requestId;
      (err as any).status = response.status;
      (err as any).body = body;
      throw err;
    }
    return { body: normalizeBody(body), requestId };
  }

  function toIntent(body: any, requestId?: string): PaymentIntent {
    return {
      id: String(body?.id ?? ""),
      hosted_url: body?.hosted_url ? String(body.hosted_url) : undefined,
      status: body?.status ? String(body.status) : "unknown",
      amount: typeof body?.amount === "number" ? body.amount : undefined,
      currency: body?.currency ? String(body.currency) : undefined,
      purpose: body?.purpose ? String(body.purpose) : undefined,
      credential_id: body?.credential_id ? String(body.credential_id) : undefined,
      request_id: requestId,
    };
  }

  return {
    async createPaymentIntent(input) {
      try {
        const { body, requestId } = await request("/payment-intents", {
          method: "POST",
          headers: { "Idempotency-Key": input.idempotency_key },
          body: JSON.stringify({ amount: input.amount, currency: input.currency, purpose: input.purpose }),
        });
        if (!body?.id) throw new Error("PASSID_PAY_INVALID_INTENT_RESPONSE");
        return toIntent(body, requestId);
      } catch (error) {
        const wrapped = new Error(`PASSID_PAY_INTENT_CREATE_FAILED:${redactError(error)}`);
        (wrapped as any).status = (error as any)?.status;
        (wrapped as any).requestId = (error as any)?.requestId;
        throw wrapped;
      }
    },
    async retrievePaymentIntent(id) {
      const { body, requestId } = await request(`/payment-intents/${encodeURIComponent(id)}`);
      return toIntent(body, requestId);
    },
    async merchantAuthorize(id) {
      const { body, requestId } = await request(`/payment-intents/${encodeURIComponent(id)}/merchant-authorize`, { method: "POST" });
      return toIntent(body, requestId);
    },
    async consent(id, input) {
      const { body, requestId } = await request(`/payment-intents/${encodeURIComponent(id)}/consent`, {
        method: "POST",
        body: JSON.stringify({ approved: input.approved, confirm_destination: input.confirm_destination }),
      });
      return toIntent(body, requestId);
    },
    async confirmDestination(id) {
      const { body, requestId } = await request(`/payment-intents/${encodeURIComponent(id)}/confirm-destination`, { method: "POST" });
      return toIntent(body, requestId);
    },
    async execute(id) {
      try {
        const { body, requestId } = await request(`/payment-intents/${encodeURIComponent(id)}/execute`, { method: "POST" });
        return toIntent(body, requestId);
      } catch (error) {
        const wrapped = new Error(`PASSID_PAY_EXECUTE_FAILED:${redactError(error)}`);
        (wrapped as any).status = (error as any)?.status;
        (wrapped as any).requestId = (error as any)?.requestId;
        throw wrapped;
      }
    },
    async listEvents(id) {
      const { body } = await request(`/payment-intents/${encodeURIComponent(id)}/events`);
      if (Array.isArray(body?.events)) return body.events;
      return Array.isArray(body) ? body : [];
    },
    async verifyCredential(id) {
      const { body } = await request(`/credentials/${encodeURIComponent(id)}/verify`, { method: "POST" });
      return { verified: body?.verified === true, status: body?.status ? String(body.status) : undefined };
    },
    async getCredentialStatus(id) {
      const { body } = await request(`/credentials/${encodeURIComponent(id)}/status`);
      return { status: body?.status ? String(body.status) : "unknown" };
    },
  };
}
