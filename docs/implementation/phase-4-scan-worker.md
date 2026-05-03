# Phase 4 Scan Worker

TrustVault Lite uses a documented mock scan worker for the Phase 4 demo. The design keeps the product flow realistic while avoiding an external malware scanning dependency during early implementation.

## Current Implementation

- Uploaded file content is written through `PrivateObjectStorage`.
- The API stores only object metadata on `document_versions`.
- Every uploaded version starts as `pending_scan`.
- The API enqueues a scan job with tenant, document, version and private storage key metadata.
- The internal worker endpoint processes one queued job for the selected tenant.
- The mock scanner marks files as `blocked` when the private object contains the demo markers `eicar` or `malware-demo`; otherwise it marks the version as `clean`.

## Storage Boundary

The storage package exposes two implementations:

- `InMemoryPrivateObjectStorage` for local tests and demo flows.
- `S3CompatiblePrivateObjectStorage` for MinIO or S3-compatible clients.

The S3-compatible adapter accepts a small client interface instead of importing a specific cloud SDK. That keeps the API testable and allows the implementation to be wired to MinIO, AWS S3 or another object store later.

## Worker Endpoint

`POST /internal/scan-jobs/process-next`

Requirements:

- authenticated user;
- active tenant context;
- role `owner` or `admin`;
- queued scan job in the current tenant.

Responses:

- `200` with processed scan job metadata when a job was handled;
- `204` when there is no queued job for the current tenant;
- `403` when the actor is not allowed to run the mock worker.

The response never returns private storage keys.

## State Transitions

```text
pending_scan -> clean
pending_scan -> blocked
```

Downloaded files must be `clean`. `pending_scan` and `blocked` versions return `409 file_not_available_until_clean_scan`.

## Audit Events

The Phase 4 flow records:

- `document.uploaded`
- `document.scan_queued`
- `document.scan_clean`
- `document.scan_blocked`
- `document.downloaded`
- `document.deleted`

Audit metadata is redacted through the shared audit package. Tokens, secrets, API keys and password-shaped fields are not stored in audit metadata.

## Upgrade Path

The mock queue is intentionally narrow. A production-oriented implementation can replace it with Redis and BullMQ while preserving the same boundaries:

- API validates and stores private objects.
- API writes `document_versions` as `pending_scan`.
- API enqueues scan jobs.
- Worker reads the private object by storage key.
- Worker writes scan results through the document repository.
- API only allows download for `clean` versions.
