# ASVS Mapping

This mapping is ASVS-inspired and does not represent certification.

| Area | TrustVault Lite Control | Evidence |
| --- | --- | --- |
| Architecture | Threat model and architecture docs | `docs/security/threat-model.md`, `docs/security/architecture.md` |
| Authentication | Development login for demo; OIDC Authorization Code Flow as production target | Auth flow tests and demo-account documentation |
| MFA | MFA/passkeys through IdP as production target | Security dashboard MFA coverage signal |
| Session Management | HttpOnly Secure SameSite cookies, revocation | Header/session tests |
| Access Control | Centralized RBAC/ABAC, deny-by-default | `packages/authz`, role tests |
| Multi-tenancy | `tenant_id`, RLS, tenant-scoped queries | migration policies, cross-tenant tests |
| Input Validation | DTO/schema validation | API tests |
| File Upload | extension allowlist, MIME sniffing, size, scanning | upload tests, worker logs |
| API Security | scopes, hashed API keys, rate limits | API integration tests |
| Audit Logging | structured audit events | audit event assertions |
| Data Protection | private storage, signed URLs | download tests |
| Error Handling | no stack traces in production | error response tests |
| Configuration | config validation at startup | config package tests |
| Dependency Security | dependency scan in CI | GitHub Actions artifact |
| Secret Handling | secret scan in CI | GitHub Actions artifact |

## Notes

- RLS is defense in depth. Authorization checks remain mandatory in code.
- Endpoints do not return raw database models; they use DTO allowlists.
- Every sensitive access denial should produce an audit event.
