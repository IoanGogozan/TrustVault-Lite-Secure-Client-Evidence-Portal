# TrustVault Lite

TrustVault Lite is a B2B multi-tenant SaaS portfolio demo built as a secure client evidence portal for confidential documents, compliance evidence, contracts, and reports.

The goal is to demonstrate real security controls in a small product. This project does not claim certification or formal compliance.

## Positioning

**ASVS-inspired secure SaaS demo, focused on tenant isolation, authorization, secure file handling, auditability, and secure SDLC.**

TrustVault Lite is inspired by:

- OWASP ASVS for secure verification requirements.
- OWASP API Security Top 10 for risks such as BOLA and BOPLA.
- OWASP File Upload Cheat Sheet for secure upload handling.
- NIST Digital Identity Guidelines for digital identity principles.
- OWASP SAMM for a simplified secure SDLC.

## Target Features

- Multi-tenant organizations with `tenant_id` on business data.
- Centralized RBAC and ABAC policy layer.
- PostgreSQL Row Level Security as defense in depth.
- Secure file uploads with validation, scanning, and private storage.
- Short-lived signed download URLs.
- Hashed API keys with scopes, expiry, and revocation.
- Audit logs and security dashboard.
- Secure sessions and MFA/passkeys through an identity provider.
- CI/CD with linting, tests, dependency scanning, secret scanning, SAST, container scanning, and ZAP baseline.

## Documentation

- [Product brief](docs/product/product-brief.md)
- [Demo script](docs/product/demo-script.md)
- [Demo accounts](docs/product/demo-accounts.md)
- [Portfolio assets](docs/product/portfolio-assets.md)
- [Implementation plan](docs/implementation/implementation-plan.md)
- [Implemented controls](docs/implementation/implemented-controls.md)
- [Definition of done](docs/implementation/definition-of-done.md)
- [Security overview](docs/security/README.md)
- [Threat model](docs/security/threat-model.md)
- [Architecture](docs/security/architecture.md)
- [ASVS mapping](docs/security/asvs-mapping.md)
- [Risk register](docs/security/risk-register.md)
- [Security test plan](docs/security/security-test-plan.md)
- [Incident response](docs/security/incident-response.md)
- [Secure SDLC](docs/security/secure-sdlc.md)

## Architecture Diagram

![TrustVault Lite security architecture](docs/assets/trustvault-security-architecture.svg)

## Proposed Repository Structure

```text
trustvault-lite/
  apps/
    web/
    api/
    worker/
  packages/
    authz/
    validation/
    audit/
    config/
  infra/
    docker/
    migrations/
  docs/
    product/
    implementation/
    security/
  .github/
    workflows/
```

## Implemented Demo Scope

- Development login with seeded users and tenant memberships.
- Tenant switcher with membership enforcement.
- Centralized authorization policy layer with role-boundary tests.
- PostgreSQL RLS migration and database-backed cross-tenant tests.
- Project and document lifecycle with mock scan processing.
- Private storage abstraction and expiring download metadata.
- Share links with hashed tokens, expiry, revocation, and max-download controls.
- API keys with hashed storage, one-time display, scopes, expiry, revocation, and external API usage.
- Audit events and security dashboard for security-relevant activity.
- Browser/API hardening with CSP, security headers, CORS, CSRF, rate limits, shape validation, and log redaction.
- GitHub Actions CI and security workflows.

## Local Development

```bash
pnpm install
pnpm db:up
pnpm db:migrate
pnpm dev:api
pnpm dev:web
```

The local PostgreSQL service is defined in `infra/docker/docker-compose.yml`.
The initial RLS migration is in `infra/migrations/0001_initial_rls.sql`.

The demo setup can also be prepared with:

```bash
pnpm demo:setup
```

Then run the API and web app in separate terminals:

```bash
pnpm dev:api
pnpm dev:web
```

Open `http://localhost:3000` and log in with `owner@acme.test`.

Database-backed integration tests are opt-in:

```bash
pnpm db:up
pnpm db:migrate
pnpm test:db
```

## Local Security Checks

```bash
pnpm test:security
```

This runs linting, unit/integration tests, type checks, and database-backed tests.

If `make` is available, equivalent targets are:

```bash
make demo
make test-security
make zap-scan
```

The ZAP scan expects the web app to be available at `http://localhost:3000` on the host machine.

## Demo Accounts

| Email | Tenant | Role |
| --- | --- | --- |
| `owner@acme.test` | Acme Corp | Owner |
| `admin@acme.test` | Acme Corp | Admin |
| `member@acme.test` | Acme Corp | Member |
| `viewer@acme.test` | Acme Corp | Viewer |
| `auditor@acme.test` | Acme Corp | Auditor |
| `owner@globex.test` | Globex | Owner |

See [demo accounts](docs/product/demo-accounts.md) for the role-by-role walkthrough.

## Security Controls Matrix

| Area | Control | Implemented Through | Testable Through |
| --- | --- | --- | --- |
| Auth | MFA / passkeys | Identity provider | Login flow |
| Sessions | Secure cookies | BFF/session config | Header tests |
| Authorization | RBAC + ABAC | `can()` policy layer | Role tests |
| Tenant isolation | RLS + `tenant_id` | PostgreSQL policies | Cross-tenant tests |
| API Security | Scoped API keys | Hash + scopes + expiry | API integration tests |
| File Security | Validation + scanning | Upload worker | Upload tests |
| Data Protection | Private storage | Signed URLs | Download tests |
| Auditability | Audit events | Audit service | Audit assertions |
| Browser Security | CSP + headers | Middleware | Header tests |
| DevSecOps | Security scans in CI | GitHub Actions | Pipeline artifacts |
| Secrets | No secrets in repo | Secret scanning | CI secret scan |
| Incident Response | Playbooks | Docs | Manual review |

## Assumed Limitations

- This is a portfolio demo, not a certified product.
- Malware scanning may start with a documented mock and later move to ClamAV.
- Billing is mocked.
- The identity provider may run locally for demo purposes, but the integration should follow OIDC Authorization Code Flow.
