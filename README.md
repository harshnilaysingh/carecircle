# CareCircle backend

Standalone TypeScript API for CareCircle. The original site UI source is unavailable in this workspace, so this repository contains the Fastify/PostgreSQL backend, Prisma migrations, Argon2id password hashing, opaque database-backed sessions, role-checked family workspaces, validation, request limits, secure headers, and audit events. The UI integration and a verified full-app deployment remain pending.

## Local setup

Requires Node.js 22.9+, pnpm 11, PostgreSQL 15+, and Redis 7+. Copy `.env.example` to `.env`, create a database, and set distinct random 32+ character `SESSION_HASH_KEY` and `INVITATION_HASH_KEY` values. Set `APP_ORIGIN` to the exact browser origin and `PUBLIC_APP_URL` to the UI base URL. Set `TRUST_PROXY=true` only when deployed behind a trusted proxy that overwrites forwarding headers; leave it false for direct access. Production invitations use Resend, so set its API key and a verified `EMAIL_FROM` sender identity.

```sh
pnpm install --frozen-lockfile
pnpm exec prisma generate
pnpm exec prisma migrate deploy
pnpm run dev
```

Production: provision managed PostgreSQL, set secrets through the platform's environment-variable manager, run `pnpm install --frozen-lockfile`, `pnpm run build`, and `pnpm exec prisma migrate deploy` as a controlled release step, then `pnpm start`. Never run migrations from concurrent production application instances. For containers, build a separate migration task with `docker build --target migrate`; run it once before shifting traffic to the runtime image. Configure TLS, backups, restore drills, monitoring, and a retention policy with the database provider.

## Routes

- `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`
- `POST /api/billing/family/base-checkout`, `POST /api/billing/stripe/webhook`
- `POST /api/families/:familyId/billing/extra-seats-checkout`
- `GET /api/families/:familyId/members`, `GET /api/families/:familyId/seat-management`
- `POST /api/families/:familyId/invites`, `POST /api/families/:familyId/invitations`
- `POST /api/family-invites/accept`, `POST /api/auth/invitations/accept`
- `DELETE /api/families/:familyId/invites/:inviteId`, `DELETE /api/families/:familyId/members/:userId`
- `GET /api/families/:familyId/records?kind=TASK&limit=50&cursor=...`
- `POST /api/families/:familyId/records`, `PATCH /api/families/:familyId/records/:recordId`, `DELETE /api/families/:familyId/records/:recordId`
- `GET /healthz`, `GET /readyz`

## Family seats and paid access

A family is created only after Stripe confirms a paid base purchase. The buyer is recorded as the family owner and occupies the first of four default seats. Owners can purchase additional seats through Stripe Checkout; the server selects the configured Stripe Price IDs and accepts only a bounded seat quantity, never an amount supplied by the browser. A verified refund event marks the associated family inactive, which blocks all family data routes.

Webhook signatures are checked against the raw request bytes and the configured endpoint signing secret. Stripe event IDs are stored in the same database transaction as family activation, seat increments, or refund handling. Purchase state also prevents multiple different Stripe event types for one Checkout Session from applying the same seat change twice. The server sends Stripe an idempotency key derived from the internal purchase record.

Create a one-use invite through `POST /api/families/:familyId/invites`; the response contains the shareable URL and raw invite code once. Only the keyed digest is stored. The link expires after seven days. Pending links do not reserve a seat. Redeeming a link requires an authenticated account, an active family, a valid pending invite, and a free seat. The PostgreSQL family row is locked while the server checks capacity and inserts the member, and the database also enforces one membership per user. The owner-only `GET .../seat-management` response includes members, unexpired pending invites, and `{ used, limit }`; remove-member and cancel-invite routes are owner-only, and the owner cannot be removed.

`GET /api/auth/me` and login/register responses expose `access.granted` and the family ID so a client can route users without an active family to purchase or invite redemption. The server remains authoritative: every family data route checks the session, the requesting membership, and active family status. Direct unpaid family creation (`POST /api/families`) returns `FAMILY_PURCHASE_REQUIRED`.

Set these environment values before enabling billing:

```dotenv
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_BASE_PRICE_ID=price_...
STRIPE_EXTRA_SEAT_PRICE_ID=price_...
# Optional. Defaults use PUBLIC_APP_URL with billing success/cancel query values.
STRIPE_SUCCESS_URL=https://your-app.example/billing/success?session_id={CHECKOUT_SESSION_ID}
STRIPE_CANCEL_URL=https://your-app.example/billing/cancelled
```

Configure the Stripe webhook URL as `https://<api-host>/api/billing/stripe/webhook` and subscribe to `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`, `checkout.session.expired`, `charge.refunded`, and `refund.created`. Use test-mode Prices and a test-mode webhook secret for development. Store all production values in the deployment platform's secret manager, never in source control. A missing local Stripe configuration disables checkout and webhook processing with a stable service error.

The migration renames the existing family/member/invitation tables to `families`, `family_members`, and `invites`. All pre-existing families become inactive because the old backend created them without payment verification. If a prototype account appeared in multiple families, the migration keeps one deterministic membership and copies displaced membership metadata into `family_member_legacy_archive`; inspect that table before applying the migration to a database with real users. The selected membership is the existing owner membership when present, otherwise the earliest membership. This archive contains identifiers and role history and should follow the same retention controls as the source database.

The source website and its UI are not present in this workspace. The API now exposes the seat-management and share-link capabilities, but wiring the app's Manage screen, native share sheet, purchase redirect, access-gate view, and invite-link login/signup flow requires the original frontend source. No UI files were changed here.

`RecordKind` identifies task, daily update, chat message, appointment, profile, care information, or household income. Each record is always scoped to a family and has validated metadata plus a bounded JSON payload. This keeps the data model extensible while the UI schema is unavailable. Income records require owner/admin reads and writes; only owners may delete them. Viewer memberships are read-only. Owners/admins manage invitations; workspace membership is checked on every request.

Record creation body:

```json
{
  "kind": "TASK",
  "title": "Pick up medication",
  "data": { "dueAt": "2026-10-19T09:00:00Z", "assignedTo": "member-id", "completed": false }
}
```

The `data` object should contain only fields required for the feature, with dates serialized as ISO-8601 strings. All browser requests must use `credentials: "include"`; mutating requests must originate from the configured `APP_ORIGIN`. The session is an HttpOnly cookie and is never returned to JavaScript. Successful create requests return the record; errors have `{ "error": { "code": "..." } }` with stable codes such as `AUTHENTICATION_REQUIRED`, `ROLE_FORBIDDEN`, `SENSITIVE_RECORD_FORBIDDEN`, and `RATE_LIMITED`.

## Security and integration limits

Session bearer tokens are random and only keyed SHA-256 digests are persisted. Cookies are HttpOnly, SameSite=Strict, and Secure in production; state-changing browser requests require the configured exact Origin. Passwords use Argon2id. Responses disable caching, Fastify Helmet adds security headers, and rate limits use Redis in production with tighter limits on authentication and invitation endpoints. Logs redact cookies; audit rows track auth and family-record changes without copying sensitive payloads. Create separate random keys for `SESSION_HASH_KEY` and `INVITATION_HASH_KEY`; do not reuse `DATABASE_URL` credentials for either.

Invitation URLs are returned only in development. Production sends invitations through Resend; the invite token is only stored as a keyed digest and delivery failures revoke the invitation. Configure a verified sender identity and secret API key. No password reset, MFA, account recovery, real-time WebSocket channel, or file upload is configured. Chat can be persisted as records; the UI should poll/refetch until a realtime transport is provisioned. Review privacy, retention, consent, and jurisdiction requirements before storing actual care or financial data.

The existing HTML/localStorage UI was not present in this workspace, so replacing its storage/auth calls and matching its exact fields is still required when the original site project is provided. `.env.example` contains placeholders only; no real account or payment credentials are stored here.

## Vercel deployment

This API is Docker-ready and now exposes the Vercel-supported Fastify entrypoint at `src/index.ts`. The GitHub repository `https://github.com/harshnilaysingh/carecircle` is public by request; the linked Vercel project `carecircle` retains SSO protection for all deployments. The earlier Vercel build failed with `STATIC_BUILD_NO_OUT_DIR` before a Fastify entrypoint was present. The new entrypoint has not yet been deployed or confirmed by Vercel. A working full-app preview still requires the original frontend source, managed PostgreSQL and Redis, Resend invitation credentials, Stripe test-mode credentials, and distinct session/invite secrets. Configure these separately for Preview and Production, set `APP_ORIGIN` to the exact frontend origin, and run migration deploy as a controlled release step. Do not put credentials in the public repository.
