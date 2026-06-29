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
- `POST /api/passid/connections/:id/revoke`
- `POST /api/webhooks/passid`
- `GET /api/admin/passid`

## PASSID Flow

1. Candidate applies to a job.
2. CareerBridge maps job verification requirements to approved PASSID scopes.
3. CareerBridge backend creates a PASSID Connect session using `PASSID_SECRET_KEY`.
4. Candidate opens the hosted PASSID authorization URL.
5. PASSID redirects to `PASSID_REDIRECT_URL` with `state`.
6. CareerBridge validates server-side state and retrieves the session from PASSID.
7. CareerBridge stores status-oriented verification results only.
8. Employer sees permitted verification status.
9. Candidate can revoke access.
10. Webhooks update connection and consent state.

## Railway Variables

Set real values in Railway. Do not commit secrets.

```env
PASSID_API_BASE_URL=https://api.passid.io
PASSID_SECRET_KEY=
PASSID_PUBLISHABLE_KEY=
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

`PASSID_ENVIRONMENT=live` rejects `sk_test_` and `pk_test_` keys. `PASSID_ENVIRONMENT=sandbox` rejects live keys.

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
- Webhook HMAC verification, timestamp window, and replay protection
- Sanitized admin views and audit logs
- No PASSID secret key in frontend responses
# CAREERBRIDGE
