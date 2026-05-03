import { DatabasePool, withTenantContext } from "@trustvault/database";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { buildApp } from "./app.js";
import { PostgresDocumentRepository } from "./documents.js";
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

  it("creates documents in the selected tenant even when body contains foreign tenant fields", async () => {
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

    expect(response.statusCode).toBe(201);
    expect(response.json().document).toMatchObject({
      tenantId: tenantAId,
      projectId: tenantAProjectId,
      title: "Tenant A Member Upload"
    });
    expect(response.json().document).not.toHaveProperty("storageKey");
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
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
      [tenantAProjectId, tenantAId, ownerUserId]
    );
    await tx.execute(
      `INSERT INTO documents (id, tenant_id, project_id, title, classification, created_by, deleted_at)
       VALUES ($1, $2, $3, 'Tenant A Evidence', 'confidential', $4, NULL)
       ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, deleted_at = NULL`,
      [tenantADocumentId, tenantAId, tenantAProjectId, ownerUserId]
    );
  });

  await withTenantContext(database, tenantBId, async (tx) => {
    await tx.execute(
      `INSERT INTO projects (id, tenant_id, name, classification, created_by)
       VALUES ($1, $2, 'Tenant B Project', 'confidential', $3)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
      [tenantBProjectId, tenantBId, ownerUserId]
    );
    await tx.execute(
      `INSERT INTO documents (id, tenant_id, project_id, title, classification, created_by, deleted_at)
       VALUES ($1, $2, $3, 'Tenant B Evidence', 'confidential', $4, NULL)
       ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, deleted_at = NULL`,
      [tenantBDocumentId, tenantBId, tenantBProjectId, ownerUserId]
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
  const cookie = response.headers["set-cookie"];

  if (typeof cookie !== "string") {
    throw new Error("Expected login to set a session cookie");
  }

  return cookie;
}

