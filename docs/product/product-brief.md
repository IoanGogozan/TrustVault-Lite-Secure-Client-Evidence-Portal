# Product Brief: TrustVault Lite

## Problema

Echipele mici au nevoie de un spatiu securizat unde pot centraliza documente confidentiale, dovezi de compliance, contracte si rapoarte fara sa expuna datele intre clienti sau roluri.

TrustVault Lite demonstreaza cum se construieste un mini SaaS multi-tenant cu securitate proiectata de la inceput.

## Public tinta

- Startup-uri B2B care pregatesc audituri sau due diligence.
- Echipe mici de compliance, legal sau customer success.
- Recruiteri si evaluatori tehnici care vor sa vada controale de securitate reale intr-un demo.

## Obiectiv portfolio

Proiectul trebuie sa arate maturitate tehnica prin combinatia dintre:

- aplicatie functionala;
- threat model;
- architecture diagram;
- ASVS mapping;
- teste de securitate;
- audit logs;
- CI/CD security pipeline;
- demo script clar.

## Functionalitati principale

- Create organization.
- Invite members.
- Tenant switcher.
- Projects.
- Secure document upload.
- File scan status.
- Secure download.
- Expiring share links.
- RBAC si ABAC.
- API keys cu scopes.
- Audit log viewer.
- Security dashboard.
- Support access cu break-glass controlat si logat.

## Roluri

| Rol | Permisiuni |
| --- | --- |
| Owner | Gestioneaza tenant-ul, billing mock, security settings si membri |
| Admin | Gestioneaza proiecte, documente, invitatii si audit |
| Member | Upload/download pe proiectele unde are acces |
| Viewer | Doar citire |
| Auditor | Citire plus audit logs, fara modificari |
| Support Operator | Rol intern, fara acces implicit la datele tenant-ului |

## Principiu cheie

Autentificarea spune cine este utilizatorul. Autorizarea decide ce poate face in tenant-ul curent.

Fiecare request trebuie sa treaca prin access control centralizat si sa fie deny-by-default.

