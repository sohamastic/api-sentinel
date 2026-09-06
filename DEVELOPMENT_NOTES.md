# Development notes

API Sentinel is a hackathon prototype for testing API security controls. The
current version includes the gateway, dashboard, configurable policies,
synthetic attack scenarios, persistent local storage, tests, and supporting
documentation.

## Current scope

- Verifies signed tokens and checks object ownership.
- Detects suspicious input and request bursts.
- Filters sensitive response fields.
- Records decisions and shows the evidence in the dashboard.
- Lets an operator review events and adjust enforcement policies.

## Validation

- Security unit tests: 20 passing.
- Development server integration checks: 11 passing.
- TypeScript checks and production build: passing.

## Follow-up work

- Add authentication for dashboard administrators.
- Run full responsive and cross-browser testing.
- Add retention rules and production telemetry.
- Support deployment as an external reverse proxy.

The included API and attack data are synthetic and intended for demonstrations.
