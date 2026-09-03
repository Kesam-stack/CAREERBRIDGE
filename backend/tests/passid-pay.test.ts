import { afterEach, describe, expect, it } from "bun:test";
import type { CareerBridgeEnv } from "../src/env";
import { createPassidPayClient } from "../src/passid-pay";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

const env = {
  PASSID_PAY_API_BASE_URL: "https://api.passid.io/v1/pay",
  PASSID_PAY_SECRET_KEY: "pay_test_contract",
} as CareerBridgeEnv;

describe("PASSID Pay HTTP client contract", () => {
  it("sends recipient, policy, and idempotency data and performs merchant authorization", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      if (String(input).endsWith("/merchant-authorize")) {
        return Response.json({ data: { id: "pi_123", state: "requires_recipient_consent" } });
      }
      return Response.json({ data: { id: "pi_123", state: "requires_merchant_authorization", hosted_url: "https://app.passid.io/pay/pi_123" } });
    }) as typeof fetch;

    const client = createPassidPayClient(env);
    const created = await client.createPaymentIntent({
      amount: 120000,
      currency: "USD",
      purpose: "contractor_payout",
      recipient: { connection_id: "conn_123", destination_id: "dst_123" },
      policy_id: "pol_contractor_payout_v1",
      idempotency_key: "payout-123",
    });
    const authorized = await client.merchantAuthorize(created.id);

    expect(created.status).toBe("requires_merchant_authorization");
    expect(authorized.status).toBe("requires_recipient_consent");
    expect(calls[0].url).toBe("https://api.passid.io/v1/pay/payment-intents");
    expect(calls[0].init?.headers).toMatchObject({
      Authorization: "Bearer pay_test_contract",
      "Idempotency-Key": "payout-123",
    });
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      amount: 120000,
      currency: "USD",
      purpose: "contractor_payout",
      recipient: { connection_id: "conn_123", destination_id: "dst_123" },
      policy_id: "pol_contractor_payout_v1",
    });
    expect(calls[1].url).toBe("https://api.passid.io/v1/pay/payment-intents/pi_123/merchant-authorize");
  });

  it("normalizes completed execution and verifies the issued credential", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/verify")) {
        return Response.json({ data: { valid: true, credential_status: "active" } });
      }
      return Response.json({ data: {
        intent: { id: "pi_123", state: "completed" },
        outcome: "completed",
        credential_id: "cred_123",
        credential_status: "active",
      } });
    }) as typeof fetch;

    const client = createPassidPayClient(env);
    const executed = await client.execute("pi_123");
    const verified = await client.verifyCredential(executed.credential_id!);

    expect(executed).toMatchObject({ id: "pi_123", status: "completed", outcome: "completed", credential_id: "cred_123", credential_status: "active" });
    expect(verified).toEqual({ verified: true, status: "active" });
  });
});
