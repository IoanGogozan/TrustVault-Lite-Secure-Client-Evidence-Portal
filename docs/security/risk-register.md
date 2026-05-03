# Risk Register

| ID | Risc | Impact | Probabilitate | Mitigare | Status |
| --- | --- | --- | --- | --- | --- |
| R-001 | Cross-tenant data access prin IDOR/BOLA | Critic | Medie | tenant-scoped queries, RLS, object-level auth, tests | Open |
| R-002 | Field-level data leak prin response generic | Ridicat | Medie | DTO allowlist, serializers per rol, tests | Open |
| R-003 | Upload fisier periculos | Ridicat | Medie | validation, scan, quarantine, private storage | Open |
| R-004 | API key compromis | Ridicat | Medie | hash, prefix, scopes, expiry, revoke, audit | Open |
| R-005 | Escaladare rol prin mass assignment | Ridicat | Medie | request allowlist, policy layer, role tests | Open |
| R-006 | Sesiune furata | Ridicat | Scazuta/Medie | HttpOnly Secure SameSite, MFA, revoke | Open |
| R-007 | Brute force login/invite/API | Mediu | Medie | Redis rate limiting, audit events | Open |
| R-008 | Logare secrete | Ridicat | Medie | log redaction, tests, secret scan | Open |
| R-009 | CORS/CSRF misconfiguration | Ridicat | Medie | CORS allowlist, CSRF tokens, SameSite | Open |
| R-010 | Support access abuziv | Ridicat | Scazuta | break-glass approval, time limit, audit | Open |

## Status values

- `Open`: riscul exista si necesita implementare.
- `Mitigated`: controlul este implementat si testat.
- `Accepted`: risc acceptat explicit pentru demo, cu justificare.

