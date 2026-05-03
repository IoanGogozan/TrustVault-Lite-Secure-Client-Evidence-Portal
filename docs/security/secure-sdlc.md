# Secure SDLC

## Obiectiv

Securitatea trebuie sa fie parte din procesul de dezvoltare, nu o verificare adaugata la final.

## Cerinte pentru schimbari

- Orice feature nou care atinge date tenant-scoped include threat notes.
- Orice endpoint nou are test de authn/authz.
- Orice model business are `tenant_id`, unde se aplica.
- Orice response public foloseste DTO allowlist.
- Orice secret sau token este redactat in logs.
- Orice upload/download are audit event.

## Pull Request Checklist

- [ ] Endpoint-urile noi cer auth.
- [ ] Autorizarea este verificata prin policy layer.
- [ ] Query-urile sunt tenant-scoped.
- [ ] Nu exista `findById(id)` fara tenant context pentru resurse business.
- [ ] DTO-urile nu expun campuri interne.
- [ ] Exista teste negative pentru acces interzis.
- [ ] Audit events sunt create pentru actiuni sensibile.
- [ ] Nu se logheaza secrete.
- [ ] Config nou validat la startup.
- [ ] Documentatia relevanta este actualizata.

## CI/CD Security Pipeline

Pipeline-ul tinta ruleaza:

1. install
2. lint
3. unit tests
4. integration tests
5. authorization tests
6. dependency scan
7. secret scan
8. SAST
9. container scan
10. build
11. OWASP ZAP baseline
12. generate security report artifact

## Release Hardening

- Verifica security headers.
- Verifica CORS allowlist.
- Verifica CSRF protection.
- Ruleaza seed demo si scenariul principal.
- Ruleaza testele cross-tenant.
- Revizuieste risk register.

