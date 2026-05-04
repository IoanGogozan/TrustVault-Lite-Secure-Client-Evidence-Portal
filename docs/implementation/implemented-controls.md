# Implemented Controls

This document summarizes the implemented demo controls that are useful for portfolio review. It replaces the phase-by-phase development notes with a stable evidence-oriented view.

## Document Scan Worker

- Uploaded file content is written through `PrivateObjectStorage`.
- Document versions start as `pending_scan`.
- The API enqueues a tenant-scoped scan job.
- The mock worker marks files as `blocked` when content contains `eicar` or `malware-demo`; otherwise the version becomes `clean`.
- Downloads are allowed only for `clean` versions.
- Responses never expose private storage keys.

Relevant events:

- `document.uploaded`
- `document.scan_queued`
- `document.scan_clean`
- `document.scan_blocked`
- `document.downloaded`
- `document.deleted`

## Private Storage Boundary

- `InMemoryPrivateObjectStorage` supports local tests and demos.
- `S3CompatiblePrivateObjectStorage` defines an adapter boundary for MinIO or S3-compatible clients.
- The S3-compatible adapter accepts a small client interface instead of importing a cloud SDK directly.
- API responses expose expiring download metadata, not object paths, bucket names, or storage keys.

## Share Links

- Share link tokens are generated with high entropy and shown only once.
- Share link tokens use opaque `tv_share_<linkId>.<secret>` values and do not encode tenant IDs.
- Stored records contain only the secret hash in `token_hash`.
- Links can expire, enforce `maxDownloads`, and be revoked.
- Public share link responses include expiring download metadata only.
- Share link creation requires update access to the target document.
- Public link usage remains tenant-scoped during lookup.

Relevant events:

- `share_link.created`
- `share_link.revoked`
- `share_link.used`
- `share_link.denied`

## API Keys

- API keys use generated `tv_live_...` values.
- The full key is returned only during creation.
- API keys use opaque `tv_live_<keyId>.<secret>` values and do not encode tenant IDs.
- Stored records contain only the secret hash in `key_hash`.
- List and revoke responses expose only metadata such as `keyPrefix`, scopes, expiry, and status.
- External API requests require `Authorization: Bearer <key>`.
- Revoked and expired keys are rejected.
- Read-only keys cannot create documents.
- Audit metadata includes only `keyPrefix`, never the full key.

External API:

- `GET /api/v1/documents`
- `POST /api/v1/documents`

## Audit and Security Dashboard

- `GET /audit-events` supports filtering by `actorType`, `action`, `result`, and `limit`.
- `GET /security-dashboard` requires `security:read`.
- Dashboard metrics include MFA coverage, access denied events, file scan status, active API keys, and active share links.
- Risky events highlight denied access, API key lifecycle changes, share link activity, and blocked file scans.
- Dashboard responses remain tenant-scoped and do not expose secrets, raw tokens, API key hashes, or storage keys.

## Browser and API Hardening

- API responses include baseline security headers.
- CORS is allowlisted to local web origins.
- Browser-origin mutating session requests require `X-CSRF-Token`.
- Browser-like mutating session requests with missing or unknown origins are rejected.
- API key Bearer requests are excluded from CSRF checks.
- Request body size is limited at the Fastify boundary.
- Error responses use stable error codes and do not expose stack traces.
- Demo rate limits protect login, API keys, external API calls, share links, and uploads.
- Rate limit subjects hash bearer tokens before they are used as limiter keys.
- A Redis-compatible rate limiter adapter exists for multi-instance deployments.
- Request shape validation rejects unknown body and query keys on current endpoints.
- Production API logging redacts authorization headers, cookies, CSRF tokens, API keys, tokens, passwords, and file payloads.

## Internal Worker Controls

- Scan result updates require an internal worker token.
- Scan job processing requires an internal worker token.
- Local demos use `X-Internal-Worker-Token: trustvault-demo-worker`.
- Production deployments should set `INTERNAL_WORKER_TOKEN` and keep scan endpoints off the public edge.

## DevSecOps

- CI workflow runs install, lint, typecheck, tests, PostgreSQL-backed tests, and build.
- Security workflow runs dependency scanning, secret scanning, CodeQL SAST, Trivy scanning, OWASP ZAP baseline, and a security report artifact.
- Dependabot is configured for npm and GitHub Actions updates.
- ZAP is non-blocking for the demo until a stable baseline is triaged.

## Known Demo Limits

- Development login is used for local demo speed and is disabled in production mode.
- Production identity is expected to use OIDC Authorization Code Flow with MFA or passkeys.
- Malware scanning uses a documented mock worker instead of ClamAV.
- Redis and S3-compatible adapters are present as boundaries, but local demo defaults remain in-memory.
- SBOM generation is planned for release artifacts but is not implemented yet.
