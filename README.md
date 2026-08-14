# CareerBridge

CareerBridge is a separate institution application that integrates PASSID as an external customer. It is intentionally isolated from the PASSID institution dashboard and behaves like a simplified Handshake-style marketplace for candidates, employers, and university partners.

Identity and credential verification powered by PASSID.

## Architecture

```text
CareerBridge browser
  -> CareerBridge backend
  -> PASSID secret key stored only in Railway/backend env
  -> https://api.passid.io
```

The browser never receives `PASSID_SECRET_KEY` or `PASSID_WEBHOOK_SECRET`.

## Projects

```text
careerbridge/
  backend/    Hono + Bun + SQLite API
  web/        React + Vite frontend
  database/   schema notes
  scripts/    operational scripts
  railway.json
  .env.example
```

## Backend Routes

- `GET /health`
- `GET /version`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/jobs`
- `GET /api/jobs/:id`
- `POST /api/jobs/:id/apply`
- `POST /api/employer/jobs`
- `GET /api/applications`
- `GET /api/employer/applicants/:id`
- `POST /api/passid/connect/sessions`
- `GET /api/passid/callback`
- `GET /api/passid/connections`
- `POST /api/passid/connections/:id/revoke`
- `POST /api/webhooks/passid`
- `GET /api/admin/passid`

## PASSID Flow

1. Candidate applies to a job.
2. CareerBridge maps job verification requirements to approved PASSID scopes.
3. CareerBridge generates a PKCE verifier/challenge, encrypts the verifier server-side, and creates a PASSID Connect session using `PASSID_CONNECT_KEY`.
4. Candidate opens the hosted PASSID authorization URL.
5. PASSID redirects to `PASSID_REDIRECT_URL` with a one-time authorization `code` and the original `state`.
6. CareerBridge validates `state` and exchanges the code plus PKCE verifier at `POST /v1/connect/token`.
7. Only after that exchange succeeds does CareerBridge fetch granted scopes and clear the stored verifier.
8. CareerBridge stores status-oriented verification results only.
9. Employer sees permitted verification status.
10. Candidate can revoke access, and webhooks update connection lifecycle state.

## Railway Variables

Set real values in Railway. Do not commit secrets.

```env
PASSID_CONNECT_BASE=https://api.passid.io/api/sandbox/connect
PASSID_CONNECT_KEY=
PASSID_WEBHOOK_SECRET=
PASSID_ENVIRONMENT=sandbox
PASSID_REDIRECT_URL=
PASSID_WEBHOOK_URL=
APP_URL=
API_URL=
DATABASE_URL=
SESSION_SECRET=
ENCRYPTION_KEY=
```

For approved live access, set `PASSID_CONNECT_BASE=https://api.passid.io/v1/connect`. `PASSID_ENVIRONMENT=live` rejects `sk_test_` keys, and sandbox mode rejects live keys or the production Connect URL. The older `PASSID_API_BASE_URL` and `PASSID_SECRET_KEY` names remain supported during migration.

PASSID derives your registered institution from `PASSID_CONNECT_KEY`; do not send or hard-code an institution ID. Public CareerBridge signup creates candidate or pending employer accounts only. Institution workspace access remains in PASSID's institution portal.

After adding the registered institution's sandbox key, verify it without printing the key:

```bash
bun run passid:check
```

A successful check returns `{"ok":true,...}`. You can also use the admin-only `GET /api/admin/passid/readiness` endpoint from the deployed app.

In the PASSID institution dashboard, finish the external setup before an end-to-end test:

1. Create a sandbox Connect key and save it as `PASSID_CONNECT_KEY` in Railway.
2. Register `PASSID_REDIRECT_URL` as an allowed Connect return URL.
3. Register `PASSID_WEBHOOK_URL` under Webhooks and copy its signing secret to `PASSID_WEBHOOK_SECRET`.
4. Run `bun run passid:check`, then complete a hosted sandbox flow with both the success and partial-consent test users.

Do not use the PASSID partner code, institution portal password, or a user PassID code as `PASSID_CONNECT_KEY`.

## Local Development

```bash
bun --cwd careerbridge/backend test
bun --cwd careerbridge/web build
```

Demo users:

- `amara@careerbridge.test`
- `recruiter@careerbridge.test`
- `admin@careerbridge.test`

Password: `CareerBridgeDemo!2026`

## Security Controls

- Server-side sessions with HTTP-only cookies
- CSRF header for mutating authenticated routes
- PBKDF2 password hashing for registered users
- Role-based access checks
- Scope allowlist enforcement
- PASSID callback state hashing and one-time use
- S256 PKCE on Connect sessions, with AES-256-GCM encrypted verifier storage and one-time cleanup
- Webhook raw-body HMAC verification and event-ID replay protection
- Idempotency keys on hosted-session creation and authorization-code exchange
- Server-side authorization-code exchange and partial-consent handling
- Sanitized admin views and audit logs
- No PASSID secret key in frontend responses
# CAREERBRIDGE
