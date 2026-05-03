# Definition of Done

Aplicatia este gata pentru portfolio cand raspunsurile de mai jos sunt demonstrabile in aplicatie, teste si documentatie.

| Intrebare | Raspuns demonstrabil |
| --- | --- |
| Cum izolezi tenant-ii? | `tenant_id`, RLS, teste cross-tenant |
| Cum previi IDOR/BOLA? | object-level authorization + negative tests |
| Cum controlezi rolurile? | RBAC/ABAC centralizat |
| Cum protejezi fisierele? | private storage, validation, scan, signed URLs |
| Cum gestionezi sesiunile? | secure cookies, revoke, active sessions |
| Cum detectezi evenimente suspecte? | audit logs + security dashboard |
| Cum e securizat API-ul? | scoped API keys, rate limits, no mass assignment |
| Cum demonstrezi secure SDLC? | docs, threat model, CI security scans |
| Cum e verificabil? | teste automate + security report |

## Ce trebuie evitat

- JWT in localStorage.
- Verificari de rol doar in frontend.
- Endpoint-uri fara tenant check.
- `findById(id)` fara `tenant_id`.
- Upload public direct in bucket.
- API responses care returneaza obiecte intregi fara allowlist.
- Token-uri/API keys in logs.
- Parole sau reset tokens in plaintext.
- CORS wildcard.
- Lipsa testelor negative.
- README care spune doar "secure app" fara evidence.

