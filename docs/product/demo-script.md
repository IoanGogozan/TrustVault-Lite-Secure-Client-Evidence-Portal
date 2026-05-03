# Demo Script

Acesta este scenariul principal pentru portfolio sau interviu.

## Flow

1. Login ca Owner in tenant-ul `Acme Corp`.
2. Arata ca tenant-ul cere MFA sau ca userul are MFA activ.
3. Creeaza proiectul `SOC 2 Evidence`.
4. Incarca un PDF.
5. Arata statusul `pending_scan`, apoi `clean`.
6. Invita un user cu rol `Viewer`.
7. Login ca Viewer.
8. Viewer-ul poate descarca documentul, dar nu poate face upload.
9. Incearca manual accesarea unui document din alt tenant prin schimbarea ID-ului.
10. API-ul returneaza `403`.
11. Security dashboard afiseaza evenimentul `document.cross_tenant_denied`.
12. Creeaza un API key cu scope `documents:read`.
13. Incearca `DELETE /api/v1/documents/:id` cu acel key.
14. API-ul returneaza `403`.
15. Revoca cheia.
16. Arata audit log-ul complet.
17. Arata CI pipeline-ul cu security checks.

## Mesaj de prezentare

TrustVault Lite nu este prezentat ca produs certificat. Este un demo ASVS-inspired care arata controale verificabile pentru izolarea tenant-ilor, autorizare, upload securizat, auditabilitate si secure SDLC.

