# Architecture

## Context

TrustVault Lite este un SaaS B2B multi-tenant format din frontend, API, worker, PostgreSQL, Redis, object storage si identity provider.

## Component Diagram

```mermaid
flowchart LR
  Browser[Browser] --> Web[Next.js Web]
  Web --> API[API]
  API --> IdP[OIDC Provider]
  API --> DB[(PostgreSQL + RLS)]
  API --> Redis[(Redis)]
  API --> Storage[(Private S3/MinIO)]
  API --> Queue[Queue]
  Queue --> Worker[Worker]
  Worker --> Scanner[ClamAV or Scan Mock]
  Worker --> DB
  Worker --> Storage
```

## Auth Flow

```mermaid
sequenceDiagram
  participant U as User
  participant W as Web
  participant I as OIDC Provider
  participant A as API

  U->>W: Login
  W->>I: Authorization Code Flow
  I-->>W: Authorization code
  W->>I: Exchange code
  I-->>W: ID/access data
  W->>A: Create app session
  A-->>W: HttpOnly Secure SameSite cookie
```

## Tenant Request Flow

```mermaid
sequenceDiagram
  participant W as Web/API Client
  participant A as API
  participant P as Policy Layer
  participant D as PostgreSQL

  W->>A: Request with selected tenant
  A->>A: Authenticate actor
  A->>A: Verify active membership
  A->>P: can(actor, action, resource)
  P-->>A: allow/deny
  A->>D: set_config(app.current_tenant_id)
  D-->>A: tenant-scoped result
  A-->>W: Response DTO allowlist
```

## Upload Flow

```mermaid
sequenceDiagram
  participant U as User
  participant A as API
  participant S as Storage
  participant Q as Queue
  participant W as Worker
  participant DB as Database

  U->>A: Upload document
  A->>A: Authz + file validation
  A->>S: Store private object
  A->>DB: Create version pending_scan
  A->>Q: Enqueue scan job
  Q->>W: Scan job
  W->>S: Read object
  W->>W: Scan
  W->>DB: Mark clean or blocked
```

## Download Flow

1. Actor cere download.
2. API autentifica actorul.
3. API verifica tenant, rol, proiect si scan status.
4. API refuza fisierele care nu sunt `clean`.
5. API creeaza signed URL scurt si expirabil.
6. API logheaza audit event.

## Data Model

Tabele principale:

- `users`
- `tenants`
- `memberships`
- `projects`
- `documents`
- `document_versions`
- `share_links`
- `api_keys`
- `audit_events`
- `support_access_requests`

## Browser Hardening

Header-ele minime:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy`

