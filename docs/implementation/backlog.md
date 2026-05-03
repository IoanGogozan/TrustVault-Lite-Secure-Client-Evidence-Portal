# Backlog

## MVP 1: SaaS Foundation

- Landing page simplu.
- Register/login prin OIDC sau Auth.js.
- Create organization.
- Tenant switcher.
- Invite user by email.
- Accept invite.
- Roluri: Owner, Admin, Member, Viewer, Auditor.
- Dashboard tenant.

Security focus:

- userul nu poate vedea tenant-uri unde nu este membru;
- toate query-urile sunt tenant-scoped;
- toate endpoint-urile cer auth;
- deny by default.

## MVP 2: Document Vault

- Projects.
- Upload document.
- File versioning simplu.
- Download securizat.
- Delete soft.
- File scan status.
- Audit events pentru upload/download/delete.

Security focus:

- fisiere private;
- signed URLs expirabile;
- file validation;
- scan inainte de download;
- documentele nu pot fi accesate cross-tenant.

## MVP 3: Authorization Hardening

- Policy layer centralizat.
- Tests pentru fiecare rol.
- Tests pentru cross-tenant access.
- Tests pentru API object ID manipulation.
- Field-level response filtering.

Security focus:

- prevenire IDOR/BOLA;
- prevenire mass assignment;
- nu returnam campuri sensibile accidental;
- fiecare access denied intra in audit log.

## MVP 4: Security Dashboard

- Audit log viewer.
- Security events page.
- API key management.
- Active sessions page.
- MFA status page.
- Share links page.

Security focus:

- vizibilitate;
- trasabilitate;
- revocare rapida;
- evidence pentru controale.

## MVP 5: DevSecOps

- GitHub Actions.
- Lint si tests.
- Dependency scan.
- Secret scanning.
- SAST.
- Container scan.
- OWASP ZAP baseline scan.
- SBOM.
- Security checklist in README.

Security focus:

- securitatea este parte din proces, nu doar cod.

