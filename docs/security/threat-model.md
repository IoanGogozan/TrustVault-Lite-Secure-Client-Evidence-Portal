# Threat Model

## Scope

Acest threat model acopera TrustVault Lite ca SaaS B2B multi-tenant pentru documente confidentiale.

## Assets

| Asset | Sensibilitate | Observatii |
| --- | --- | --- |
| Documente incarcate | Ridicata | Contracte, rapoarte, dovezi compliance |
| Metadata documente | Medie/Ridicata | Titluri, clasificari, owner, proiect |
| Tenant data | Ridicata | Membri, roluri, setari |
| Audit logs | Ridicata | Pot contine evenimente de securitate si metadata |
| API keys | Critica | Se salveaza doar hash, cheia reala se afiseaza o singura data |
| Sesiuni | Critica | Cookies HttpOnly Secure SameSite |
| Share links | Ridicata | Token hash-uit, expirare, max downloads |

## Actori

| Actor | Descriere |
| --- | --- |
| User legitim | Membru al unui tenant |
| Owner/Admin | User cu drepturi administrative |
| Viewer/Auditor | User cu drepturi limitate |
| API client | Sistem extern care foloseste API key |
| Support Operator | Operator intern fara acces implicit la datele tenant-ului |
| Atacator extern | Nu are cont sau are cont compromis |
| Insider rau intentionat | User legitim care incearca escaladare sau cross-tenant access |

## Trust Boundaries

- Browser utilizator -> Web app.
- Web app -> API.
- API -> Database.
- API -> Object storage.
- API -> Redis/rate limiter.
- API -> Queue/worker.
- Worker -> Malware scanner.
- API -> Identity provider.
- GitHub Actions -> build/deploy artifacts.

## STRIDE

| Categorie | Risc | Mitigare |
| --- | --- | --- |
| Spoofing | Sesiune furata sau API key compromis | HttpOnly cookies, MFA, session revoke, API key expiry/revoke |
| Tampering | Modificare role/project/document neautorizata | RBAC/ABAC, DTO allowlist, audit log |
| Repudiation | User neaga actiunea | Audit events cu actor, IP hash, user agent, result |
| Information Disclosure | Cross-tenant document access | tenant-scoped queries, RLS, object-level auth, negative tests |
| Denial of Service | Upload-uri mari sau brute force | file size limits, body limits, rate limiting |
| Elevation of Privilege | Viewer devine Admin prin mass assignment | allowlist de campuri, centralized authorization, tests |

## Scenarii prioritare

### BOLA / IDOR

Un user modifica `documentId` in URL si incearca sa acceseze documentul altui tenant.

Mitigari:

- verifica membership activa in tenant;
- verifica `document.tenantId`;
- seteaza RLS transaction context;
- returneaza `403` sau `404` fara leak de metadata;
- logheaza `document.cross_tenant_denied`.

### BOPLA / field leak

Un endpoint returneaza obiectul complet si expune `storage_key`, `token_hash` sau metadata interna.

Mitigari:

- response DTO allowlist;
- serializers per rol;
- teste pentru campuri interzise.

### Upload malicious file

Un atacator incarca fisier cu extensie permisa dar continut periculos.

Mitigari:

- allowlist extensii;
- MIME sniffing;
- magic bytes;
- max file size;
- storage privat;
- scan job;
- quarantine pana la `clean`.

### API key misuse

O cheie cu `documents:read` este folosita pentru delete.

Mitigari:

- scopes per endpoint;
- cheia este hash-uita;
- expiry si revoke;
- rate limiting;
- audit event pentru deny.

### Support access abuse

Operator intern incearca sa vada date tenant fara aprobare.

Mitigari:

- support operator nu are acces implicit;
- break-glass access necesita aprobare, motiv si expirare;
- fiecare acces este logat high-risk.

