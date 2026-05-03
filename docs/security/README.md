# Security Overview

TrustVault Lite este proiectat ca demo SaaS securizat, cu controale vizibile si testabile.

## Principii

- Security by design.
- Deny by default.
- Least privilege.
- Tenant isolation peste tot.
- Defense in depth.
- Auditabilitate pentru actiuni sensibile.
- Secure SDLC verificabil.

## Documente

- [Threat model](threat-model.md)
- [Architecture](architecture.md)
- [ASVS mapping](asvs-mapping.md)
- [Risk register](risk-register.md)
- [Security test plan](security-test-plan.md)
- [Incident response](incident-response.md)
- [Secure SDLC](secure-sdlc.md)

## Controale principale

- OIDC Authorization Code Flow.
- MFA/passkeys prin identity provider.
- HttpOnly Secure SameSite cookies.
- RBAC/ABAC centralizat.
- PostgreSQL RLS.
- Upload validation si scanare.
- Private object storage.
- Signed URLs expirabile.
- API keys hash-uite cu scopes.
- Rate limiting.
- Audit events.
- Security headers.
- CSRF protection.
- CI/CD security scans.

