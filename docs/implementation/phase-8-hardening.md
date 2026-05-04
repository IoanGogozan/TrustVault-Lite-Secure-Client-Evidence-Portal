# Phase 8: Frontend and Backend Hardening

Phase 8 adds baseline browser, request, and session safety controls for the demo API and web client.

## Implemented Scope

- Security headers are applied to API responses:
  - `Content-Security-Policy`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Cross-Origin-Resource-Policy`
  - `Strict-Transport-Security` in production
- CORS remains allowlisted to local web origins and now allows `X-CSRF-Token`.
- Session login sets a readable CSRF cookie alongside the HttpOnly session cookie.
- Browser-origin mutating requests with session cookies must send `X-CSRF-Token`.
- API key Bearer requests are excluded from CSRF checks.
- Request body size is limited at the Fastify boundary.
- Error responses use stable error codes and do not expose stack traces.
- The web client sends CSRF tokens for mutating session-backed requests.
- In-memory demo rate limits protect login, API keys, external API calls, share links, and uploads.
- A Redis-compatible rate limiter adapter is available for multi-instance deployments.
- Audit event filters validate actor and result values before querying.
- A central request shape validator rejects unknown body and query keys on existing endpoints.
- Production API logging uses structured redaction for authorization headers, cookies, CSRF tokens, API keys, tokens, passwords, and file payloads.
- Frontend responses define CSP and baseline browser security headers through Next.js config.

## Security Notes

- CSRF is enforced for credentialed browser requests detected by an allowed `Origin` header.
- Public share-link reads and external API key calls remain usable without CSRF tokens.
- The demo uses a double-submit CSRF token pattern because the web and API run on separate local ports.
- The CSP on API responses is intentionally strict because API routes should not render active browser content.

## Verification

- Tests cover security headers, CORS allowed headers, CSRF rejection and acceptance, request body limits, and no stack trace leakage.
- Tests cover login rate limiting and invalid audit filter rejection.
- Tests cover unknown mass-assignment fields and the Redis-compatible limiter contract.
- Existing authorization, tenant isolation, file, share-link, API key, and dashboard tests continue to pass.

## Remaining Hardening

- Wire the Redis-compatible rate limiter to a real Redis client in deployed environments.
- Move request shape rules into a reusable schema library when the API surface grows.
