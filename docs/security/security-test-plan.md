# Security Test Plan

## Unit Tests

- `can()` permite doar actiuni definite explicit.
- `can()` este deny-by-default.
- wildcard permissions functioneaza doar pentru aria corecta.
- response DTO nu include campuri sensibile.
- API key hash/verify functioneaza fara a expune cheia.

## Integration Tests

- user neautentificat primeste `401`.
- user fara membership primeste `403`.
- user nu poate selecta tenant strain.
- document ID din alt tenant returneaza `403` sau `404`.
- query fara tenant context esueaza.
- API key din tenant A nu acceseaza tenant B.
- viewer nu poate upload.
- auditor nu poate crea documente.
- admin nu poate modifica owner.

## File Upload Tests

- fisier prea mare este respins.
- extensie nepermisa este respinsa.
- MIME mismatch este respins.
- fisier `pending_scan` nu poate fi descarcat.
- fisier `blocked` nu poate fi descarcat.
- storage key nu este expus in API response.
- download link expira.

## API Security Tests

- cheie fara `documents:write` nu poate crea document.
- cheie revocata nu functioneaza.
- cheie expirata nu functioneaza.
- rate limiting se aplica pe tenant, key si IP.
- request body cu campuri extra nu modifica proprietati interzise.
- cheia completa nu apare in logs.

## Browser/HTTP Tests

- CSP este prezent.
- HSTS este prezent in production.
- `X-Content-Type-Options: nosniff` este prezent.
- `X-Frame-Options: DENY` este prezent.
- CORS blocheaza origin necunoscut.
- mutating request fara CSRF token este blocat.
- erorile nu expun stack trace in production.

## CI Security Checks

- dependency scan.
- secret scan.
- SAST.
- container scan.
- OWASP ZAP baseline.
- SBOM generation.

