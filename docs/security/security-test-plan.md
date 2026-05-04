# Security Test Plan

## Unit Tests

- `can()` allows only explicitly defined actions.
- `can()` denies by default.
- wildcard permissions work only for the correct area.
- response DTO does not include sensitive fields.
- API key hash/verify works without exposing the key.

## Integration Tests

- unauthenticated user receives `401`.
- user without membership receives `403`.
- user cannot select a foreign tenant.
- document ID from another tenant returns `403` or `404`.
- query without tenant context fails.
- API key from tenant A cannot access tenant B.
- viewer cannot upload.
- auditor cannot create documents.
- admin cannot modify owner.

## File Upload Tests

- file that is too large is rejected.
- forbidden extension is rejected.
- MIME mismatch is rejected.
- `pending_scan` file cannot be downloaded.
- `blocked` file cannot be downloaded.
- storage key is not exposed in API response.
- download link expires.

## API Security Tests

- key without `documents:write` cannot create documents.
- revoked key does not work.
- expired key does not work.
- rate limiting applies by tenant, key, and IP.
- request body with extra fields cannot modify forbidden properties.
- full key does not appear in logs.

## Browser/HTTP Tests

- CSP is present.
- HSTS is present in production.
- `X-Content-Type-Options: nosniff` is present.
- `X-Frame-Options: DENY` is present.
- CORS blocks unknown origin.
- mutating request without CSRF token is blocked.
- errors do not expose stack traces in production.

## CI Security Checks

- dependency scan.
- secret scan.
- SAST.
- container scan.
- OWASP ZAP baseline.
- SBOM generation for future release artifacts.
