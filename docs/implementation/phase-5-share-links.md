# Phase 5 Share Links

Phase 5 adds expiring public download links for clean documents.

## Implemented Controls

- Share link tokens are generated with high entropy and shown only once.
- The stored share link record contains only `token_hash`; the raw token is never returned by list or revoke APIs.
- Public access uses the token hash for lookup.
- Links can expire.
- Links can enforce `maxDownloads`.
- Links can be revoked.
- Public access never exposes private storage keys or internal object paths.
- Share link lifecycle events are written to the audit trail.

## API Surface

Authenticated tenant APIs:

- `GET /share-links`
- `POST /share-links`
- `DELETE /share-links/:shareLinkId`

Public API:

- `GET /public/share-links/:token`

## Audit Events

- `share_link.created`
- `share_link.revoked`
- `share_link.used`
- `share_link.denied`

## Security Notes

Share links are only creatable by actors who can update the target document. This prevents read-only viewers from creating public access paths.

Public share link responses include expiring download metadata only. The response does not include `tokenHash`, `storageKey`, bucket names, or internal object paths.

The public token contains an opaque tenant hint so the PostgreSQL repository can set tenant context before token hash lookup. RLS remains active during public share link resolution.
