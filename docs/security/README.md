# Security Overview

TrustVault Lite is designed as a secure SaaS demo with visible and testable controls.

## Principles

- Security by design.
- Deny by default.
- Least privilege.
- Tenant isolation everywhere.
- Defense in depth.
- Auditability for sensitive actions.
- Verifiable secure SDLC.

## Documents

- [Threat model](threat-model.md)
- [Architecture](architecture.md)
- [ASVS mapping](asvs-mapping.md)
- [Risk register](risk-register.md)
- [Security test plan](security-test-plan.md)
- [Incident response](incident-response.md)
- [Secure SDLC](secure-sdlc.md)

## Main Controls

- Development-only demo login for local portfolio flows.
- Production identity target: OIDC Authorization Code Flow.
- Production MFA/passkeys through identity provider.
- HttpOnly Secure SameSite cookies.
- Centralized RBAC/ABAC.
- PostgreSQL RLS.
- Upload validation and scanning.
- Private object storage.
- Expiring signed URLs.
- Hashed API keys with scopes.
- Rate limiting.
- Audit events.
- Security headers.
- CSRF protection.
- CI/CD security scans.
