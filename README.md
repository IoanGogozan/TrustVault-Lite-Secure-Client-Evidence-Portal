# TrustVault Lite

TrustVault Lite este un demo SaaS B2B multi-tenant pentru portfolio, construit ca un "secure client evidence portal" pentru documente, dovezi de compliance, contracte si fisiere confidentiale.

Scopul proiectului este sa demonstreze controale reale de securitate aplicate intr-un produs mic, nu sa pretinda certificare sau conformitate formala.

## Pozitionare

**ASVS-inspired secure SaaS demo, focused on tenant isolation, authorization, secure file handling, auditability and secure SDLC.**

TrustVault Lite este inspirat de:

- OWASP ASVS pentru cerinte de verificare securizata.
- OWASP API Security Top 10 pentru riscuri precum BOLA si BOPLA.
- OWASP File Upload Cheat Sheet pentru upload securizat.
- NIST Digital Identity Guidelines pentru principii de identitate digitala.
- OWASP SAMM pentru secure SDLC simplificat.

## Functionalitati tinta

- Organizatii multi-tenant cu `tenant_id` peste tot.
- RBAC si ABAC centralizat prin policy layer.
- PostgreSQL Row Level Security ca defense in depth.
- Upload securizat de fisiere cu validare, scanare si storage privat.
- Link-uri de download semnate, expirabile si auditabile.
- API keys hash-uite, cu scopes, expirare si revocare.
- Audit logs si security dashboard.
- Sesiuni securizate, MFA/passkeys prin identity provider.
- CI/CD cu lint, teste, dependency scan, secret scan, SAST, container scan si ZAP baseline.

## Documentatie

- [Product brief](docs/product/product-brief.md)
- [Demo script](docs/product/demo-script.md)
- [Implementation plan](docs/implementation/implementation-plan.md)
- [Backlog](docs/implementation/backlog.md)
- [Definition of done](docs/implementation/definition-of-done.md)
- [Security overview](docs/security/README.md)
- [Threat model](docs/security/threat-model.md)
- [Architecture](docs/security/architecture.md)
- [ASVS mapping](docs/security/asvs-mapping.md)
- [Risk register](docs/security/risk-register.md)
- [Security test plan](docs/security/security-test-plan.md)
- [Incident response](docs/security/incident-response.md)
- [Secure SDLC](docs/security/secure-sdlc.md)

## Structura repo propusa

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

## Faze MVP

1. SaaS foundation: auth, tenant-uri, memberships, invite-uri.
2. Document vault: proiecte, upload, scan status, download securizat.
3. Authorization hardening: policy layer, teste negative, field-level filtering.
4. Security dashboard: audit logs, API keys, sesiuni, MFA status, share links.
5. DevSecOps: pipeline de securitate si rapoarte verificabile.

## Security Controls Matrix

| Arie | Control | Implementat prin | Testabil prin |
| --- | --- | --- | --- |
| Auth | MFA / passkeys | Identity provider | Login flow |
| Sessions | Secure cookies | BFF/session config | Header tests |
| Authorization | RBAC + ABAC | `can()` policy layer | Role tests |
| Tenant isolation | RLS + `tenant_id` | PostgreSQL policies | Cross-tenant tests |
| API Security | Scoped API keys | Hash + scopes + expiry | API integration tests |
| File Security | Validation + scan | Upload worker | Upload tests |
| Data Protection | Private storage | Signed URLs | Download tests |
| Auditability | Audit events | Audit service | Audit assertions |
| Browser Security | CSP + headers | Middleware | Header tests |
| DevSecOps | Security scans in CI | GitHub Actions | Pipeline artifacts |
| Secrets | No secrets in repo | Secret scan | CI secret scanning |
| Incident Response | Playbooks | Docs | Manual review |

## Limitari asumate

- Proiectul este demo de portfolio, nu produs certificat.
- Malware scanning poate porni cu mock documentat si trece ulterior la ClamAV.
- Billing este mock.
- Identity provider-ul poate fi local pentru demo, dar integrarea trebuie sa respecte OIDC Authorization Code Flow.

