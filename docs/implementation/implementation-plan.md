# Implementation Plan

## Implementation Principles

- Build incrementally through verifiable phases.
- Every endpoint is authenticated by default.
- Every business query is tenant-scoped.
- Authorization is centralized in the policy layer.
- PostgreSQL RLS is defense in depth, not a replacement for code-level authorization.
- Negative tests are required for cross-tenant access and role boundaries.
- Do not log passwords, tokens, API keys, raw files, or unnecessary PII.

## Recommended Stack

| Component | Choice |
| --- | --- |
| Frontend | Next.js / React + TypeScript |
| Backend | NestJS or Fastify with TypeScript |
| Database | PostgreSQL |
| Multi-tenancy | `tenant_id` everywhere plus PostgreSQL RLS |
| Auth | OIDC provider or Auth.js |
| Sessions | HttpOnly Secure SameSite cookies |
| File storage | S3-compatible storage, local MinIO |
| Queue | Redis + BullMQ |
| Malware scan | ClamAV container or documented mock |
| Rate limiting | Redis-based |
| CI/CD | GitHub Actions |

## Phase 0: Repository and Initial Documentation

Deliverables:

- monorepo setup;
- Docker Compose;
- `apps/web`;
- `apps/api`;
- `apps/worker`;
- `packages/authz`;
- `packages/audit`;
- `packages/validation`;
- `packages/config`;
- `docs/security`;
- initial threat model;
- architecture diagram;
- security README.

## Phase 1: Auth and Tenant Model

Tasks:

- Configure OIDC/Auth provider.
- Create the `users` model.
- Create the `tenants` model.
- Create the `memberships` model.
- Implement tenant switcher.
- Create authentication middleware.
- Create tenant context middleware.
- Configure secure session cookies.
- Add logout and session revocation.

Tests:

- unauthenticated user receives `401`;
- user without membership receives `403`;
- user cannot select a foreign tenant;
- session cookie has `HttpOnly`, `Secure`, `SameSite`.

## Phase 2: RBAC and Policy Layer

Tasks:

- Define permissions.
- Create roles.
- Create the `can()` function.
- Create guards/middleware for endpoints.
- Create `requirePermission("document:read")`.
- Create audit event for `authorization.denied`.

Initial permissions:

```ts
export const permissions = {
  owner: [
    "tenant:update",
    "members:invite",
    "members:update_role",
    "documents:*",
    "audit:read",
    "api_keys:*",
    "security:read"
  ],
  admin: [
    "members:invite",
    "documents:*",
    "audit:read",
    "api_keys:read"
  ],
  member: [
    "documents:create",
    "documents:read",
    "documents:update"
  ],
  viewer: [
    "documents:read"
  ],
  auditor: [
    "documents:read",
    "audit:read",
    "security:read"
  ]
} as const;
```

Tests:

- viewer cannot upload;
- member cannot change roles;
- admin cannot modify owner;
- auditor cannot create documents;
- missing permission results in deny.

## Phase 3: PostgreSQL RLS

Tasks:

- Add `tenant_id` to all business tables.
- Enable RLS.
- Create policies.
- Set `app.current_tenant_id` per request/transaction.
- Add integration tests for cross-tenant leakage.

Example:

```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_documents
ON documents
USING (
  tenant_id = current_setting('app.current_tenant_id')::uuid
);
```

## Phase 4: Document Vault and Upload Pipeline

Status: nearly complete.

Completed:

- Create `projects`.
- Create upload endpoint.
- Validate extension, MIME, and size.
- Calculate SHA-256.
- Store file in private storage.
- Create scan job.
- Mark document as `pending_scan`.
- Worker marks the file as `clean` or `blocked`.
- Allow download only for `clean` files.
- Expose expiring download metadata without leaking private storage keys.
- Show the project, document, upload, scan, download, and audit flow in the web UI.
- Provide a minimal audit viewer for generated lifecycle events.

Current worker note:

- Phase 4 starts with a documented mock scan worker in `docs/implementation/phase-4-scan-worker.md`.
- The mock queue can be replaced with Redis and BullMQ without changing the document upload boundary.

## Phase 5: Share Links

Status: implemented for the current demo scope.

Completed:

- Create expiring links.
- Store token as a hash.
- Add `max_downloads`.
- Allow revocation.
- Log each access.
- Do not expose storage path.

Implementation note:

- Details are documented in `docs/implementation/phase-5-share-links.md`.

## Phase 6: API Keys and External API

Status: implemented for the current demo scope.

Completed:

- Generate API keys with prefix.
- Display the full key only once.
- Store only a hash.
- Add scopes.
- Add expiry.
- Add revoke.
- Add scoped external document APIs.
- Track `last_used_at`.
- Reject revoked and expired keys.
- Audit successful and denied API key usage.

Implementation note:

- Details are documented in `docs/implementation/phase-6-api-keys.md`.

Remaining hardening:

- Add rate limits.
- Add OpenAPI spec.

Format:

```text
tv_live_7f3a9c_xxxxxxxxxxxxxxxxxxxxxxxxx
```

## Phase 7: Audit Logs and Security Dashboard

Status: implemented for the current demo scope.

Completed:

- Create audit event filtering.
- Create audit viewer.
- Create filters by actor, action, and result.
- Create security events dashboard.
- Create simple alert rules.
- Show MFA coverage, denied access, file scan status, active API keys, active share links, and risky events in the web UI.

Implementation note:

- Details are documented in `docs/implementation/phase-7-audit-security-dashboard.md`.

Remaining hardening:

- Extract a dedicated audit query service for PostgreSQL-backed audit queries.
- Add persisted alert acknowledgements.
- Add time-windowed dashboard metrics.

## Phase 8: Frontend/Backend Hardening

Status: implemented for the current demo scope.

Completed:

- Add API CSP and baseline security headers.
- Keep credentialed CORS allowlisted.
- Add CSRF protection for browser-origin mutating session requests.
- Add request body limits.
- Add stable error responses without stack traces.
- Send CSRF tokens from the web client for mutating session-backed requests.
- Add demo rate limits for login, API keys, external API, share links, and uploads.
- Add a Redis-compatible rate limiter adapter for multi-instance deployments.
- Add frontend CSP and browser security headers through Next.js config.
- Validate audit query filters.
- Reject unknown body and query keys through centralized request shape validation.
- Add structured production logging redaction for sensitive headers and payload fields.
- Keep existing output filtering for sensitive document, share-link, and API key fields.

Implementation note:

- Details are documented in `docs/implementation/phase-8-hardening.md`.

Remaining hardening:

- Wire the Redis-compatible rate limiter to a real Redis client in deployment.
- Move request shape validation into reusable route schemas as the API grows.

## Phase 9: CI/CD Security

Status: implemented for the current demo scope.

Completed:

- Install dependencies.
- Run lint checks.
- Run unit tests.
- Run integration tests.
- Run database-backed PostgreSQL RLS tests.
- Run authorization tests.
- Run dependency scan.
- Run secret scan.
- Run SAST.
- Run filesystem and container-style scan.
- Build the application.
- Run OWASP ZAP baseline.
- Generate security report artifact.
- Configure Dependabot for npm and GitHub Actions updates.

Implementation note:

- Details are documented in `docs/implementation/phase-9-devsecops.md`.

Remaining hardening:

- Add a dedicated Docker image build once production container files exist.
- Add SBOM generation for release artifacts.
- Promote ZAP findings from non-blocking to blocking after a stable baseline file is created.

## Phase 10: Portfolio Polish

- short demo video;
- screenshots;
- architecture diagram;
- security controls matrix;
- demo accounts;
- seed data;
- `make demo`;
- `make test-security`;
- `make zap-scan`;
- well-structured public README.
