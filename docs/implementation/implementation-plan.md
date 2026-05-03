# Implementation Plan

## Principii de implementare

- Construim incremental, pe faze verificabile.
- Fiecare endpoint este autentificat implicit.
- Fiecare query business este tenant-scoped.
- Autorizarea este centralizata in policy layer.
- PostgreSQL RLS este defense in depth, nu inlocuitor pentru verificarea din cod.
- Testele negative sunt obligatorii pentru cross-tenant access si roluri.
- Nu logam parole, token-uri, API keys, fisiere brute sau PII inutil.

## Stack recomandat

| Componenta | Alegere |
| --- | --- |
| Frontend | Next.js / React + TypeScript |
| Backend | NestJS sau Fastify cu TypeScript |
| Database | PostgreSQL |
| Multi-tenancy | `tenant_id` peste tot + PostgreSQL RLS |
| Auth | OIDC provider sau Auth.js |
| Sessions | HttpOnly Secure SameSite cookies |
| Storage fisiere | S3-compatible storage, MinIO local |
| Queue | Redis + BullMQ |
| Malware scan | ClamAV container sau mock documentat |
| Rate limiting | Redis-based |
| CI/CD | GitHub Actions |

## Faza 0: Repo si documentatie initiala

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
- threat model initial;
- architecture diagram;
- security README.

## Faza 1: Auth si tenant model

Task-uri:

- Configureaza OIDC/Auth provider.
- Creeaza modelul `users`.
- Creeaza modelul `tenants`.
- Creeaza modelul `memberships`.
- Implementeaza tenant switcher.
- Creeaza middleware de autentificare.
- Creeaza middleware de tenant context.
- Configureaza session cookies securizate.
- Adauga logout si session revoke.

Teste:

- user neautentificat primeste `401`;
- user fara membership primeste `403`;
- user nu poate selecta tenant strain;
- session cookie are `HttpOnly`, `Secure`, `SameSite`.

## Faza 2: RBAC si policy layer

Task-uri:

- Defineste permissions.
- Creeaza rolurile.
- Creeaza functia `can()`.
- Creeaza guard/middleware pentru endpoint-uri.
- Creeaza helper `requirePermission("document:read")`.
- Creeaza audit event pentru `authorization.denied`.

Permisiuni initiale:

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

Teste:

- viewer nu poate upload;
- member nu poate schimba roluri;
- admin nu poate modifica owner;
- auditor nu poate crea documente;
- orice permisiune lipsa duce la deny.

## Faza 3: PostgreSQL RLS

Task-uri:

- Adauga `tenant_id` pe toate tabelele business.
- Activeaza RLS.
- Creeaza policies.
- Seteaza `app.current_tenant_id` per request/transaction.
- Creeaza teste de integrare pentru cross-tenant leakage.

Exemplu:

```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_documents
ON documents
USING (
  tenant_id = current_setting('app.current_tenant_id')::uuid
);
```

## Faza 4: Document vault si upload pipeline

Task-uri:

- Creeaza `projects`.
- Creeaza upload endpoint.
- Valideaza extensie, MIME si size.
- Calculeaza SHA-256.
- Salveaza fisierul in storage privat.
- Creeaza scan job.
- Marcheaza documentul `pending_scan`.
- Worker-ul marcheaza `clean` sau `blocked`.
- Permite download doar pentru fisiere `clean`.

## Faza 5: Share links

Task-uri:

- Creeaza link-uri expirabile.
- Salveaza tokenul hash-uit.
- Adauga `max_downloads`.
- Permite revocarea.
- Logheaza fiecare acces.
- Nu expune storage path.

## Faza 6: API keys si external API

Task-uri:

- Genereaza API keys cu prefix.
- Afiseaza cheia completa o singura data.
- Salveaza doar hash.
- Adauga scopes.
- Adauga expiry.
- Adauga revoke.
- Adauga rate limits.
- Adauga OpenAPI spec.

Format:

```text
tv_live_7f3a9c_xxxxxxxxxxxxxxxxxxxxxxxxx
```

## Faza 7: Audit logs si security dashboard

Task-uri:

- Creeaza audit event service.
- Creeaza audit viewer.
- Creeaza filtre dupa actor, action si result.
- Creeaza security events dashboard.
- Creeaza alert rules simple.

## Faza 8: Hardening frontend/backend

Task-uri:

- CSP.
- Security headers.
- CORS allowlist.
- CSRF protection.
- Request body limits.
- Input validation.
- Output encoding.
- Error handling fara stack traces in production.
- Structured logs cu redactare.
- Config validation la startup.

## Faza 9: CI/CD security

Pipeline:

1. install
2. lint
3. unit tests
4. integration tests
5. authorization tests
6. dependency scan
7. secret scan
8. SAST
9. container scan
10. build
11. OWASP ZAP baseline
12. generate security report artifact

## Faza 10: Portfolio polish

- demo video scurt;
- screenshots;
- architecture diagram;
- security controls matrix;
- demo accounts;
- seed data;
- `make demo`;
- `make test-security`;
- `make zap-scan`;
- README public bine structurat.

