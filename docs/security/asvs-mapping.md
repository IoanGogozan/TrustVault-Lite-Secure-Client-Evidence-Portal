# ASVS Mapping

Aceasta mapare este ASVS-inspired si nu reprezinta certificare.

| Arie | Control TrustVault Lite | Evidence |
| --- | --- | --- |
| Architecture | Threat model si architecture docs | `docs/security/threat-model.md`, `docs/security/architecture.md` |
| Authentication | OIDC Authorization Code Flow | Auth integration docs/tests |
| MFA | MFA/passkeys prin IdP | Login flow si security dashboard |
| Session Management | HttpOnly Secure SameSite cookies, revoke | Header/session tests |
| Access Control | RBAC/ABAC centralizat, deny-by-default | `packages/authz`, role tests |
| Multi-tenancy | `tenant_id`, RLS, tenant-scoped queries | migration policies, cross-tenant tests |
| Input Validation | DTO/schema validation | API tests |
| File Upload | extension allowlist, MIME sniffing, size, scan | upload tests, worker logs |
| API Security | scopes, hash API keys, rate limits | API integration tests |
| Audit Logging | structured audit events | audit event assertions |
| Data Protection | private storage, signed URLs | download tests |
| Error Handling | no stack traces in production | error response tests |
| Configuration | config validation at startup | config package tests |
| Dependency Security | dependency scan in CI | GitHub Actions artifact |
| Secret Handling | secret scan in CI | GitHub Actions artifact |

## Notes

- RLS este defense in depth. Verificarile de autorizare raman obligatorii in cod.
- Endpoint-urile nu returneaza modele brute din DB; folosesc DTO allowlist.
- Orice access denied sensibil trebuie sa genereze audit event.

