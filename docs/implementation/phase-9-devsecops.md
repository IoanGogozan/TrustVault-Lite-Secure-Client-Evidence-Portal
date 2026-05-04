# Phase 9: DevSecOps Pipeline

Phase 9 adds GitHub Actions workflows for repeatable quality and security checks.

## Implemented Scope

- CI workflow for install, lint, typecheck, tests, PostgreSQL-backed tests, and build.
- Security workflow for dependency scanning, secret scanning, CodeQL SAST, Trivy filesystem/container-style scanning, OWASP ZAP baseline, and a security report artifact.
- Dependabot configuration for npm and GitHub Actions updates.
- Architecture diagram asset saved in `docs/assets/trustvault-security-architecture.svg`.

## Security Notes

- The CI workflow runs database-backed tests against a real PostgreSQL service and applies the RLS migration before integration tests.
- ZAP baseline is non-blocking for the portfolio demo because baseline findings should be triaged manually.
- Trivy uploads SARIF results to GitHub code scanning.
- CodeQL is configured for JavaScript and TypeScript.

## Verification

- Local verification should still run `pnpm lint`, `pnpm test`, `pnpm typecheck`, `pnpm build`, and `pnpm test:db`.
- GitHub Actions provide pipeline artifacts and code scanning output after push.

## Remaining Hardening

- Add a dedicated Docker image build once production container files exist.
- Add SBOM generation for release artifacts.
- Promote ZAP findings from non-blocking to blocking after a stable baseline file is created.
