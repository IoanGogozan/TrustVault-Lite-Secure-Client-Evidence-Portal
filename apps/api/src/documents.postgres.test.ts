import { DatabasePool, withTenantContext } from "@trustvault/database";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { buildApp } from "./app.js";
import { PostgresApiKeyRepository } from "./api-keys.js";
import { PostgresDocumentRepository } from "./documents.js";
import { PostgresProjectRepository } from "./projects.js";
import { PostgresShareLinkRepository } from "./share-links.js";
import {
  createDemoStore,
  type AppStore,
  type MembershipRole,
  type MembershipStatus
} from "./domain.js";

const runDbTests = process.env.RUN_DB_TESTS === "1";
const databaseUrl =
  process.env.DATABASE_URL ??
  "postgres://trustvault_app:trustvault_app_dev_password@localhost:5432/trustvault";

const tenantAId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const tenantBId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ownerUserId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const memberUserId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const tenantAProjectId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const tenantBProjectId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const tenantADocumentId = "11111111-2222-4333-8444-555555555555";
const tenantBDocumentId = "66666666-7777-4888-8999-000000000000";

describe.skipIf(!runDbTests)("PostgreSQL document RLS integration", () => {
  let database: DatabasePool;

  beforeAll(async () => {
    database = new DatabasePool({ connectionString: databaseUrl });
    await seedDatabase(database);
  });

  afterAll(async () => {
    await database.close();
  });

  it("lists only documents visible in the selected tenant context", async () => {
    const app = buildApp({
      store: createUuidStore(),
      documentRepository: new PostgresDocumentRepository(database)
    });
    const cookie = await login(app, "owner-db@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/documents",
      headers: { cookie, "x-tenant-id": tenantAId }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().documents).toEqual([
      expect.objectContaining({
        id: tenantADocumentId,
        tenantId: tenantAId,
        title: "Tenant A Evidence"
      })
    ]);
    expect(JSON.stringify(response.json())).not.toContain(tenantBDocumentId);
  });

  it("returns not found for a foreign tenant document hidden by RLS", async () => {
    const app = buildApp({
      store: createUuidStore(),
      documentRepository: new PostgresDocumentRepository(database)
    });
    const cookie = await login(app, "owner-db@acme.test");

    const response = await app.inject({
      method: "GET",
      url: `/documents/${tenantBDocumentId}`,
      headers: { cookie, "x-tenant-id": tenantAId }
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "document_not_found" });
  });

  it("rejects foreign tenant fields before document creation", async () => {
    const app = buildApp({
      store: createUuidStore(),
      documentRepository: new PostgresDocumentRepository(database)
    });
    const cookie = await login(app, "member-db@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/documents",
      headers: { cookie, "x-tenant-id": tenantAId },
      payload: {
        title: "Tenant A Member Upload",
        projectId: tenantAProjectId,
        classification: "confidential",
        tenantId: tenantBId,
        storageKey: "attacker-controlled-path"
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "invalid_request_body" });
  });

  it("stores document versions behind tenant RLS and blocks download until scan is clean", async () => {
    const app = buildApp({
      store: createUuidStore(),
      documentRepository: new PostgresDocumentRepository(database)
    });
    const memberCookie = await login(app, "member-db@acme.test");
    const ownerCookie = await login(app, "owner-db@acme.test");

    const uploadResponse = await app.inject({
      method: "POST",
      url: `/documents/${tenantADocumentId}/versions`,
      headers: { cookie: memberCookie, "x-tenant-id": tenantAId },
      payload: pdfUploadPayload()
    });

    expect(uploadResponse.statusCode).toBe(201);
    expect(uploadResponse.json().version).toMatchObject({
      documentId: tenantADocumentId,
      originalFilename: "database-evidence.pdf",
      mimeType: "application/pdf",
      sizeBytes: 5,
      scanStatus: "pending_scan"
    });
    expect(uploadResponse.json().version).not.toHaveProperty("storageKey");

    const pendingDownloadResponse = await app.inject({
      method: "GET",
      url: `/documents/${tenantADocumentId}/download`,
      headers: { cookie: memberCookie, "x-tenant-id": tenantAId }
    });

    expect(pendingDownloadResponse.statusCode).toBe(409);
    expect(pendingDownloadResponse.json()).toEqual({
      error: "file_not_available_until_clean_scan"
    });

    const scanResponse = await app.inject({
      method: "POST",
      url: `/document-versions/${uploadResponse.json().version.id}/scan-result`,
      headers: internalWorkerHeaders(ownerCookie, tenantAId),
      payload: { scanStatus: "clean" }
    });

    expect(scanResponse.statusCode).toBe(200);

    const cleanDownloadResponse = await app.inject({
      method: "GET",
      url: `/documents/${tenantADocumentId}/download`,
      headers: { cookie: memberCookie, "x-tenant-id": tenantAId }
    });

    expect(cleanDownloadResponse.statusCode).toBe(200);
    expect(cleanDownloadResponse.json().download).toMatchObject({
      documentId: tenantADocumentId,
      versionId: uploadResponse.json().version.id,
      originalFilename: "database-evidence.pdf",
      mimeType: "application/pdf",
      sizeBytes: 5,
      expiresInSeconds: 300
    });
    expect(cleanDownloadResponse.json().download).not.toHaveProperty("storageKey");
  });

  it("lists and creates projects in the selected tenant context", async () => {
    const app = buildApp({
      store: createUuidStore(),
      documentRepository: new PostgresDocumentRepository(database),
      projectRepository: new PostgresProjectRepository(database)
    });
    const cookie = await login(app, "owner-db@acme.test");

    const listResponse = await app.inject({
      method: "GET",
      url: "/projects",
      headers: { cookie, "x-tenant-id": tenantAId }
    });

    expect(listResponse.statusCode).toBe(200);
    expect(listResponse.json().projects).toEqual([
      expect.objectContaining({
        id: tenantAProjectId,
        tenantId: tenantAId,
        name: "Tenant A Project"
      })
    ]);
    expect(JSON.stringify(listResponse.json())).not.toContain(tenantBProjectId);

    const createResponse = await app.inject({
      method: "POST",
      url: "/projects",
      headers: { cookie, "x-tenant-id": tenantAId },
      payload: {
        name: "Tenant A API Evidence",
        classification: "internal"
      }
    });

    expect(createResponse.statusCode).toBe(201);
    expect(createResponse.json().project).toMatchObject({
      tenantId: tenantAId,
      name: "Tenant A API Evidence",
      classification: "internal",
      createdBy: ownerUserId
    });
  });

  it("creates lists and revokes share links in the selected tenant context", async () => {
    const app = buildApp({
      store: createUuidStore(),
      documentRepository: new PostgresDocumentRepository(database),
      shareLinkRepository: new PostgresShareLinkRepository(database)
    });
    const ownerCookie = await login(app, "owner-db@acme.test");

    const uploadResponse = await app.inject({
      method: "POST",
      url: `/documents/${tenantADocumentId}/versions`,
      headers: { cookie: ownerCookie, "x-tenant-id": tenantAId },
      payload: pdfUploadPayload()
    });
    await app.inject({
      method: "POST",
      url: `/document-versions/${uploadResponse.json().version.id}/scan-result`,
      headers: internalWorkerHeaders(ownerCookie, tenantAId),
      payload: { scanStatus: "clean" }
    });

    const createResponse = await app.inject({
      method: "POST",
      url: "/share-links",
      headers: { cookie: ownerCookie, "x-tenant-id": tenantAId },
      payload: {
        documentId: tenantADocumentId,
        maxDownloads: 2
      }
    });

    expect(createResponse.statusCode).toBe(201);
    expect(createResponse.json().shareToken).toEqual(expect.stringMatching(/^tv_share_/));
    expect(createResponse.json().shareLink).toMatchObject({
      tenantId: tenantAId,
      documentId: tenantADocumentId,
      downloadCount: 0,
      maxDownloads: 2
    });
    expect(createResponse.json().shareLink).not.toHaveProperty("tokenHash");

    const listResponse = await app.inject({
      method: "GET",
      url: "/share-links",
      headers: { cookie: ownerCookie, "x-tenant-id": tenantAId }
    });

    expect(listResponse.statusCode).toBe(200);
    expect(listResponse.json().shareLinks).toEqual([
      expect.objectContaining({
        id: createResponse.json().shareLink.id,
        tenantId: tenantAId
      })
    ]);

    const publicUseResponse = await app.inject({
      method: "GET",
      url: `/public/share-links/${createResponse.json().shareToken}`
    });

    expect(publicUseResponse.statusCode).toBe(200);
    expect(publicUseResponse.json().download).toMatchObject({
      documentId: tenantADocumentId,
      originalFilename: "database-evidence.pdf"
    });

    const revokeResponse = await app.inject({
      method: "DELETE",
      url: `/share-links/${createResponse.json().shareLink.id}`,
      headers: { cookie: ownerCookie, "x-tenant-id": tenantAId }
    });

    expect(revokeResponse.statusCode).toBe(200);
    expect(revokeResponse.json().shareLink).toHaveProperty("revokedAt");
  });

  it("creates lists and revokes API keys in the selected tenant context", async () => {
    const app = buildApp({
      store: createUuidStore(),
      documentRepository: new PostgresDocumentRepository(database),
      apiKeyRepository: new PostgresApiKeyRepository(database)
    });
    const ownerCookie = await login(app, "owner-db@acme.test");

    const createResponse = await app.inject({
      method: "POST",
      url: "/api-keys",
      headers: { cookie: ownerCookie, "x-tenant-id": tenantAId },
      payload: {
        name: "Database Integration",
        scopes: ["documents:read"],
        expiresInDays: 30
      }
    });

    expect(createResponse.statusCode).toBe(201);
    expect(createResponse.json().key).toEqual(expect.stringMatching(/^tv_live_/));
    expect(createResponse.json().apiKey).toMatchObject({
      tenantId: tenantAId,
      name: "Database Integration",
      scopes: ["documents:read"]
    });
    expect(createResponse.json().apiKey).not.toHaveProperty("keyHash");

    const listResponse = await app.inject({
      method: "GET",
      url: "/api-keys",
      headers: { cookie: ownerCookie, "x-tenant-id": tenantAId }
    });

    expect(listResponse.statusCode).toBe(200);
    expect(listResponse.json().apiKeys).toEqual([
      expect.objectContaining({
        id: createResponse.json().apiKey.id,
        tenantId: tenantAId
      })
    ]);

    const externalResponse = await app.inject({
      method: "GET",
      url: "/api/v1/documents",
      headers: { authorization: `Bearer ${createResponse.json().key}` }
    });

    expect(externalResponse.statusCode).toBe(200);
    expect(externalResponse.json().documents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: tenantADocumentId,
          tenantId: tenantAId
        })
      ])
    );

    const revokeResponse = await app.inject({
      method: "DELETE",
      url: `/api-keys/${createResponse.json().apiKey.id}`,
      headers: { cookie: ownerCookie, "x-tenant-id": tenantAId }
    });

    expect(revokeResponse.statusCode).toBe(200);
    expect(revokeResponse.json().apiKey).toHaveProperty("revokedAt");
  });
});

async function seedDatabase(database: DatabasePool): Promise<void> {
  await withTenantContext(database, tenantAId, async (tx) => {
    await tx.execute(
      `INSERT INTO users (id, email, name, identity_provider_subject)
       VALUES
         ($1, 'owner-db@acme.test', 'Database Owner', 'db-owner'),
         ($2, 'member-db@acme.test', 'Database Member', 'db-member')
       ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email`
      ,
      [ownerUserId, memberUserId]
    );
    await tx.execute(
      `INSERT INTO tenants (id, name, slug)
       VALUES
         ($1, 'Database Tenant A', 'database-tenant-a'),
         ($2, 'Database Tenant B', 'database-tenant-b')
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
      [tenantAId, tenantBId]
    );
    await tx.execute(
      `INSERT INTO projects (id, tenant_id, name, classification, created_by)
       VALUES ($1, $2, 'Tenant A Project', 'confidential', $3)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, classification = EXCLUDED.classification`,
      [tenantAProjectId, tenantAId, ownerUserId]
    );
    await tx.execute(
      `INSERT INTO documents (id, tenant_id, project_id, title, classification, created_by, deleted_at)
       VALUES ($1, $2, $3, 'Tenant A Evidence', 'confidential', $4, NULL)
       ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, current_version_id = NULL, deleted_at = NULL`,
      [tenantADocumentId, tenantAId, tenantAProjectId, ownerUserId]
    );
    await tx.execute(
      `DELETE FROM api_keys
       WHERE tenant_id = $1`,
      [tenantAId]
    );
    await tx.execute(
      `DELETE FROM share_links
       WHERE tenant_id = $1`,
      [tenantAId]
    );
    await tx.execute(
      `DELETE FROM document_versions
       WHERE tenant_id = $1
         AND document_id = $2`,
      [tenantAId, tenantADocumentId]
    );
    await tx.execute(
      `DELETE FROM documents
       WHERE tenant_id = $1
         AND project_id = $2
         AND id <> $3`,
      [tenantAId, tenantAProjectId, tenantADocumentId]
    );
    await tx.execute(
      `DELETE FROM projects
       WHERE tenant_id = $1
         AND id <> $2`,
      [tenantAId, tenantAProjectId]
    );
  });

  await withTenantContext(database, tenantBId, async (tx) => {
    await tx.execute(
      `INSERT INTO projects (id, tenant_id, name, classification, created_by)
       VALUES ($1, $2, 'Tenant B Project', 'confidential', $3)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, classification = EXCLUDED.classification`,
      [tenantBProjectId, tenantBId, ownerUserId]
    );
    await tx.execute(
      `INSERT INTO documents (id, tenant_id, project_id, title, classification, created_by, deleted_at)
       VALUES ($1, $2, $3, 'Tenant B Evidence', 'confidential', $4, NULL)
       ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, current_version_id = NULL, deleted_at = NULL`,
      [tenantBDocumentId, tenantBId, tenantBProjectId, ownerUserId]
    );
    await tx.execute(
      `DELETE FROM api_keys
       WHERE tenant_id = $1`,
      [tenantBId]
    );
    await tx.execute(
      `DELETE FROM share_links
       WHERE tenant_id = $1`,
      [tenantBId]
    );
    await tx.execute(
      `DELETE FROM document_versions
       WHERE tenant_id = $1
         AND document_id = $2`,
      [tenantBId, tenantBDocumentId]
    );
    await tx.execute(
      `DELETE FROM documents
       WHERE tenant_id = $1
         AND project_id = $2
         AND id <> $3`,
      [tenantBId, tenantBProjectId, tenantBDocumentId]
    );
    await tx.execute(
      `DELETE FROM projects
       WHERE tenant_id = $1
         AND id <> $2`,
      [tenantBId, tenantBProjectId]
    );
  });
}

function createUuidStore(): AppStore {
  const store = createDemoStore();
  const now = new Date("2026-05-03T00:00:00.000Z");

  store.users = [
    {
      id: ownerUserId,
      email: "owner-db@acme.test",
      name: "Database Owner",
      identityProviderSubject: "db-owner",
      status: "active",
      createdAt: now
    },
    {
      id: memberUserId,
      email: "member-db@acme.test",
      name: "Database Member",
      identityProviderSubject: "db-member",
      status: "active",
      createdAt: now
    }
  ];
  store.tenants = [
    {
      id: tenantAId,
      name: "Database Tenant A",
      slug: "database-tenant-a",
      plan: "demo",
      createdAt: now
    },
    {
      id: tenantBId,
      name: "Database Tenant B",
      slug: "database-tenant-b",
      plan: "demo",
      createdAt: now
    }
  ];
  store.memberships = [
    createMembership("membership_db_owner", tenantAId, ownerUserId, "owner", "active"),
    createMembership("membership_db_member", tenantAId, memberUserId, "member", "active", [
      tenantAProjectId
    ])
  ];
  store.projects = [
    {
      id: tenantAProjectId,
      tenantId: tenantAId,
      name: "Tenant A Project",
      classification: "confidential",
      createdBy: ownerUserId,
      createdAt: now
    }
  ];
  store.documents = [];
  store.documentVersions = [];
  store.scanJobs = [];
  store.storageObjects = {};
  store.auditEvents = [];
  store.sessions = [];

  return store;
}

function createMembership(
  id: string,
  tenantId: string,
  userId: string,
  role: MembershipRole,
  status: MembershipStatus,
  projectIds?: string[]
) {
  return {
    id,
    tenantId,
    userId,
    role,
    status,
    mfaRequired: true,
    ...(projectIds ? { projectIds } : {}),
    createdAt: new Date("2026-05-03T00:00:00.000Z")
  };
}

async function login(app: ReturnType<typeof buildApp>, email: string): Promise<string> {
  const response = await app.inject({
    method: "POST",
    url: "/auth/dev-login",
    payload: { email }
  });
  const cookie = headerValue(response.headers["set-cookie"]);

  if (!cookie) {
    throw new Error("Expected login to set a session cookie");
  }

  return cookie;
}

function headerValue(value: string | string[] | number | undefined): string {
  if (Array.isArray(value)) {
    return value.join("; ");
  }

  return typeof value === "string" ? value : "";
}

function internalWorkerHeaders(cookie: string, tenantId: string) {
  return {
    cookie,
    "x-tenant-id": tenantId,
    "x-internal-worker-token": "trustvault-demo-worker"
  };
}

function pdfUploadPayload() {
  const content = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2d]);

  return {
    originalFilename: "database-evidence.pdf",
    mimeType: "application/pdf",
    sizeBytes: content.byteLength,
    contentBase64: content.toString("base64")
  };
}
