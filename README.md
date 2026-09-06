# API Sentinel

A working API security lab: a request gateway, six explainable controls, a live
dashboard, persistent audit records, and nine reproducible attack scenarios.

## Run locally

Requires Node.js 22.13+ (Node 24 recommended) and npm. No cloud account or external
database is required for local use. From this directory:

```sh
npm ci
npm run db:migrate
npm run dev -- --host 127.0.0.1
```

Open the URL printed by the development server (normally http://localhost:3000).
On Windows, use `npm.cmd` if PowerShell blocks the npm script. Local D1/SQLite
state is stored in `.wrangler/state`; a normal restart preserves it.

Click **Run demo suite**. Then inspect **Events**, open a decision, and use
**Mark reviewed** or **Replay scenario**. Under **Policies**, change a tunable
rule to monitor mode with a reason and replay its scenario to compare behavior.

## What's implemented

| Control | Detection | Enforcement |
|---|---|---|
| Authentication | HS256 signature and exact issuer/audience/subject; typed issue/expiry claims | Reject invalid or expired tokens with 401 |
| Object authorization | Compare token subject to server-owned order metadata | Reject cross-user reads with 403 |
| Request contracts | Route/method allowlist, query checks, body size/type/field constraints | Reject unknown routes and malformed requests |
| Injection heuristic | Selected SQL and script patterns after Unicode normalization/comment removal | Block with 403 or record in monitor mode |
| Resource control | Atomic database counter, 10 requests per identity per fixed 60-second window | Return 429 with Retry-After or monitor |
| Response contract | Explicit profile field allowlist | Remove restricted fields or monitor synthetic exposure |

The protected demo API has four routes under `/api/gateway`:

```text
GET  /orders/:id     Alice owns ord_1001; Bob owns ord_1002
GET  /profile       Public fields: id, name, email
GET  /search?q=...  Synthetic product catalog
POST /orders       {"item":"Keyboard","quantity":1}
```

POST `/orders` validates an order; it does not create a durable order. The
synthetic profile intentionally contains internal fields so response filtering
is visible. No real credentials or customer data are used.

## Judge demo (about 4 minutes)

1. **Run the suite.** Nine scenarios produce 22 inspected requests under default
   policies: 11 allowed, 10 blocked, and one filtered response. A burst that
   crosses a fixed-window boundary may have a different split.
2. **Inspect cross-user access.** Show Alice's valid token still cannot read
   Bob's order. The dashboard explains the ownership mismatch.
3. **Inspect excessive data.** Only `id`, `name`, and `email` reach the caller.
   The event names removed properties without retaining their values.
4. **Tune a heuristic.** Set Suspicious input to Monitor, provide an audit
   reason, and replay SQL injection. The request succeeds with a monitored
   finding. Authentication and ownership cannot be disabled.
5. **Restore enforcement.** Show the audit trail and rerun the burst scenario:
   the same atomic limiter admits 10 requests and rejects the next four.

## Validation

```sh
npm test
npm run typecheck
npm run test:integration  # development server must be running
npm run build
```

Integration tests generate synthetic events and audit records, temporarily
change editable policies, and restore the original policy modes in `finally`.
They check concurrent rate enforcement, live HTTP access, invalid JSON, large
bodies, monitor behavior, CSRF rejection, review persistence, and log redaction.

## Repository map

```text
app/page.tsx                 Dashboard entry
app/api/[...path]/route.ts   Gateway and control-plane HTTP handlers
components/dashboard.tsx    Interactive operations dashboard
lib/security.ts             Independently testable security primitives
lib/gateway.ts              Request/response policy pipeline
lib/demo-api.ts             Fixed synthetic upstream adapter
lib/scenarios.ts            Controlled scenario runner
lib/store.ts                Prepared database queries and atomic counters
db/schema.ts                Drizzle schema
drizzle/                    Generated immutable SQL migrations
tests/                      Security and HTTP integration tests
docs/ARCHITECTURE.md         Design, trust boundaries, and tradeoffs
docs/SECURITY.md             Threat model and limitations
```

## Deployment and scope

The implementation uses React, TypeScript, Vinext, Cloudflare Workers, and D1.
This replaces the initially suggested Python/Redis split with one deployable
project and an atomic SQLite limiter. The security pipeline is genuine; the
upstream is an in-process synthetic API, not a proxy to an external service.

The hosted console is designed for **Sites owner-only access**. Locally it must
stay on loopback. The application does not contain a separate administrator
login: same-origin checks prevent browser CSRF but do not authenticate an
operator. Do not make the deployment public or bind the local server to a shared
network without adding operator authentication and authorization first.

Read [architecture](docs/ARCHITECTURE.md) and [security scope](docs/SECURITY.md)
before extending this into a production gateway.
