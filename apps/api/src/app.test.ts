import { describe, expect, it } from "vitest";
import { buildApp } from "./app.js";
import { createDemoStore } from "./domain.js";

describe("phase 1 auth and tenant foundation", () => {
  it("returns 401 for unauthenticated requests", async () => {
    const app = buildApp({ store: createDemoStore() });

    const response = await app.inject({ method: "GET", url: "/me" });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "unauthorized" });
  });

  it("sets secure session cookie on dev login", async () => {
    const app = buildApp({ store: createDemoStore() });

    const response = await app.inject({
      method: "POST",
      url: "/auth/dev-login",
      payload: { email: "owner@acme.test" }
    });

    expect(response.statusCode).toBe(204);

    const cookie = response.headers["set-cookie"];

    expect(cookie).toContain("tv_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Lax");
  });

  it("allows credentialed CORS only for the web origin", async () => {
    const app = buildApp({ store: createDemoStore() });

    const response = await app.inject({
      method: "OPTIONS",
      url: "/me",
      headers: {
        origin: "http://localhost:3000",
        "access-control-request-method": "GET"
      }
    });

    expect(response.statusCode).toBe(204);
    expect(response.headers["access-control-allow-origin"]).toBe("http://localhost:3000");
    expect(response.headers["access-control-allow-credentials"]).toBe("true");
  });

  it("rejects preflight requests from unknown origins", async () => {
    const app = buildApp({ store: createDemoStore() });

    const response = await app.inject({
      method: "OPTIONS",
      url: "/me",
      headers: {
        origin: "https://evil.example",
        "access-control-request-method": "GET"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "origin_not_allowed" });
  });

  it("lists only active tenant memberships for the current user", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/me",
      headers: { cookie }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      user: {
        id: "user_owner_acme",
        email: "owner@acme.test",
        name: "Acme Owner"
      },
      memberships: [
        {
          tenantId: "tenant_acme",
          tenantName: "Acme Corp",
          tenantSlug: "acme",
          role: "owner",
          mfaRequired: true
        }
      ]
    });
  });

  it("requires an explicit tenant context for tenant routes", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/tenant/current",
      headers: { cookie }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "tenant_required" });
  });

  it("rejects tenant selection for tenants where the user is not a member", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/tenant/current",
      headers: { cookie, "x-tenant-id": "tenant_globex" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "tenant_membership_required" });
  });

  it("returns current tenant context for an active member", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "viewer@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/tenant/current",
      headers: { cookie, "x-tenant-id": "tenant_acme" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      tenant: {
        id: "tenant_acme",
        name: "Acme Corp",
        slug: "acme"
      },
      membership: {
        role: "viewer",
        mfaRequired: true
      }
    });
  });

  it("revokes sessions on logout", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "owner@acme.test");

    const logout = await app.inject({
      method: "POST",
      url: "/auth/logout",
      headers: { cookie }
    });

    expect(logout.statusCode).toBe(204);

    const me = await app.inject({
      method: "GET",
      url: "/me",
      headers: { cookie }
    });

    expect(me.statusCode).toBe(401);
  });

  it("creates a tenant and assigns owner membership to the current user", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "owner@acme.test");

    const created = await app.inject({
      method: "POST",
      url: "/tenants",
      headers: { cookie },
      payload: { name: "Northwind Security", slug: "northwind-security" }
    });

    expect(created.statusCode).toBe(201);
    expect(created.json()).toMatchObject({
      tenant: {
        name: "Northwind Security",
        slug: "northwind-security",
        plan: "demo"
      }
    });

    const me = await app.inject({
      method: "GET",
      url: "/me",
      headers: { cookie }
    });

    expect(me.json().memberships).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          tenantName: "Northwind Security",
          tenantSlug: "northwind-security",
          role: "owner"
        })
      ])
    );
  });

  it("rejects duplicate tenant slugs", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/tenants",
      headers: { cookie },
      payload: { name: "Acme Corp", slug: "acme" }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual({ error: "tenant_slug_taken" });
  });

  it("lists only projects visible to the current role", async () => {
    const store = createDemoStore();
    store.projects.push({
      id: "project_acme_legal",
      tenantId: "tenant_acme",
      name: "Legal Review",
      classification: "restricted",
      createdBy: "user_owner_acme",
      createdAt: new Date("2026-05-03T00:00:00.000Z")
    });
    const app = buildApp({ store });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/projects",
      headers: { cookie, "x-tenant-id": "tenant_acme" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().projects).toEqual([
      expect.objectContaining({
        id: "project_acme_soc2",
        tenantId: "tenant_acme",
        name: "SOC 2 Evidence"
      })
    ]);
    expect(JSON.stringify(response.json())).not.toContain("project_acme_legal");
  });

  it("allows admins to create projects and records an audit event", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "admin@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/projects",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        name: "Vendor Evidence",
        classification: "internal"
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json().project).toMatchObject({
      tenantId: "tenant_acme",
      name: "Vendor Evidence",
      classification: "internal",
      createdBy: "user_admin_acme"
    });
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "project.created",
      entityType: "project",
      entityId: response.json().project.id,
      result: "success"
    });
  });

  it("denies project creation for members", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/projects",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        name: "Member Project",
        classification: "internal"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "authorization.denied",
      entityType: "project",
      result: "failure",
      metadata: expect.objectContaining({
        requestedAction: "projects:create"
      })
    });
  });

  it("allows admins to update projects and records an audit event", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "admin@acme.test");

    const response = await app.inject({
      method: "PATCH",
      url: "/projects/project_acme_soc2",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        name: "SOC 2 Evidence Room",
        classification: "restricted"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().project).toMatchObject({
      id: "project_acme_soc2",
      name: "SOC 2 Evidence Room",
      classification: "restricted"
    });
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "project.updated",
      entityType: "project",
      entityId: "project_acme_soc2",
      result: "success"
    });
  });

  it("denies project updates for members", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "PATCH",
      url: "/projects/project_acme_soc2",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        name: "Unauthorized Rename"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(store.projects.find((project) => project.id === "project_acme_soc2")?.name).toBe(
      "SOC 2 Evidence"
    );
  });

  it("allows owners to invite a new member", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/tenant/invitations",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { email: "external-auditor@acme.test", role: "auditor" }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({
      invitation: {
        tenantId: "tenant_acme",
        email: "external-auditor@acme.test",
        role: "auditor",
        status: "pending"
      }
    });
    expect(response.json().inviteToken).toEqual(expect.stringMatching(/^invite_/));
  });

  it("denies invitation creation for viewers", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "viewer@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/tenant/invitations",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { email: "new-viewer@acme.test", role: "viewer" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
    expect(store.auditEvents).toEqual([
      expect.objectContaining({
        action: "authorization.denied",
        entityType: "invitation",
        result: "failure",
        metadata: expect.objectContaining({
          requestedAction: "members:invite",
          reason: "permission_missing"
        })
      })
    ]);
  });

  it("accepts an invitation and creates an active membership", async () => {
    const app = buildApp({ store: createDemoStore() });
    const ownerCookie = await login(app, "owner@acme.test");

    const invitation = await app.inject({
      method: "POST",
      url: "/tenant/invitations",
      headers: { cookie: ownerCookie, "x-tenant-id": "tenant_acme" },
      payload: { email: "new-member@acme.test", role: "member" }
    });
    const inviteToken = invitation.json().inviteToken;

    const accepted = await app.inject({
      method: "POST",
      url: "/invitations/accept",
      payload: { token: inviteToken, name: "New Member" }
    });

    expect(accepted.statusCode).toBe(200);
    expect(accepted.headers["set-cookie"]).toContain("tv_session=");
    expect(accepted.json()).toMatchObject({
      user: {
        email: "new-member@acme.test",
        name: "New Member"
      },
      tenantId: "tenant_acme",
      role: "member"
    });

    const me = await app.inject({
      method: "GET",
      url: "/me",
      headers: { cookie: accepted.headers["set-cookie"] as string }
    });

    expect(me.statusCode).toBe(200);
    expect(me.json().memberships).toEqual([
      expect.objectContaining({
        tenantId: "tenant_acme",
        role: "member"
      })
    ]);
  });

  it("rejects invalid invitation tokens", async () => {
    const app = buildApp({ store: createDemoStore() });

    const response = await app.inject({
      method: "POST",
      url: "/invitations/accept",
      payload: { token: "invite_invalid" }
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "invite_not_found" });
  });

  it("allows owners to update member roles", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "PATCH",
      url: "/memberships/membership_acme_member/role",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { role: "viewer" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      membership: {
        id: "membership_acme_member",
        tenantId: "tenant_acme",
        userId: "user_member_acme",
        role: "viewer",
        status: "active"
      }
    });
    expect(
      store.memberships.find((membership) => membership.id === "membership_acme_member")?.role
    ).toBe("viewer");
  });

  it("allows admins to update non-owner member roles", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "admin@acme.test");

    const response = await app.inject({
      method: "PATCH",
      url: "/memberships/membership_acme_viewer/role",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { role: "member" }
    });

    expect(response.statusCode).toBe(200);
    expect(
      store.memberships.find((membership) => membership.id === "membership_acme_viewer")?.role
    ).toBe("member");
  });

  it("prevents admins from modifying owners", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "admin@acme.test");

    const response = await app.inject({
      method: "PATCH",
      url: "/memberships/membership_acme_owner/role",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { role: "viewer" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
    expect(
      store.memberships.find((membership) => membership.id === "membership_acme_owner")?.role
    ).toBe("owner");
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "authorization.denied",
      entityType: "membership",
      entityId: "membership_acme_owner",
      metadata: expect.objectContaining({
        requestedAction: "members:update_role",
        reason: "owner_role_protected"
      })
    });
  });

  it("prevents admins from assigning owner role", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "admin@acme.test");

    const response = await app.inject({
      method: "PATCH",
      url: "/memberships/membership_acme_member/role",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { role: "owner" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
    expect(
      store.memberships.find((membership) => membership.id === "membership_acme_member")?.role
    ).toBe("member");
  });

  it("denies role updates for members", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "PATCH",
      url: "/memberships/membership_acme_viewer/role",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { role: "member" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "authorization.denied",
      entityType: "membership",
      entityId: "membership_acme_viewer",
      metadata: expect.objectContaining({
        requestedAction: "members:update_role",
        reason: "permission_missing"
      })
    });
  });

  it("does not expose foreign tenant memberships through role update", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "PATCH",
      url: "/memberships/membership_globex_owner/role",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { role: "viewer" }
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "membership_not_found" });
  });

  it("filters document responses and does not expose storage internals", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "viewer@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/documents/document_acme_policy",
      headers: { cookie, "x-tenant-id": "tenant_acme" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().document).toMatchObject({
      id: "document_acme_policy",
      tenantId: "tenant_acme",
      projectId: "project_acme_soc2",
      title: "Security Policy",
      classification: "confidential"
    });
    expect(response.json().document).not.toHaveProperty("storageKey");
    expect(response.json().document).not.toHaveProperty("currentVersionId");
  });

  it("denies document creation for viewers", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "viewer@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/documents",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        title: "Viewer Upload",
        projectId: "project_acme_soc2",
        classification: "confidential"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "authorization.denied",
      entityType: "document",
      result: "failure",
      metadata: expect.objectContaining({
        requestedAction: "documents:create",
        reason: "permission_missing"
      })
    });
  });

  it("allows members to create documents but ignores tenant mass assignment", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/documents",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        title: "Evidence Upload",
        projectId: "project_acme_soc2",
        classification: "confidential",
        tenantId: "tenant_globex",
        storageKey: "attacker-controlled-path"
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json().document).toMatchObject({
      tenantId: "tenant_acme",
      title: "Evidence Upload",
      projectId: "project_acme_soc2"
    });
    expect(response.json().document).not.toHaveProperty("storageKey");
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "document.created",
      entityType: "document",
      entityId: response.json().document.id,
      result: "success",
      metadata: expect.objectContaining({
        projectId: "project_acme_soc2",
        classification: "confidential"
      })
    });
  });

  it("denies document deletion for members", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "DELETE",
      url: "/documents/document_acme_policy",
      headers: { cookie, "x-tenant-id": "tenant_acme" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
    expect(store.documents.find((document) => document.id === "document_acme_policy")).not.toHaveProperty(
      "deletedAt"
    );
  });

  it("denies document creation for auditors", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "auditor@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/documents",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        title: "Audit Upload",
        projectId: "project_acme_soc2"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
  });

  it("logs authorization denial for cross-tenant document access", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/documents/document_globex_contract",
      headers: { cookie, "x-tenant-id": "tenant_acme" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
    expect(store.auditEvents.at(-1)).toMatchObject({
      tenantId: "tenant_acme",
      actorUserId: "user_owner_acme",
      action: "authorization.denied",
      entityType: "document",
      entityId: "document_globex_contract",
      result: "failure",
      metadata: expect.objectContaining({
        requestedAction: "documents:read",
        reason: "tenant_mismatch",
        resourceTenantId: "tenant_globex"
      })
    });
  });

  it("allows owners to soft delete documents", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "DELETE",
      url: "/documents/document_acme_policy",
      headers: { cookie, "x-tenant-id": "tenant_acme" }
    });

    expect(response.statusCode).toBe(204);
    expect(store.documents.find((document) => document.id === "document_acme_policy")?.deletedAt)
      .toBeInstanceOf(Date);
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "document.deleted",
      entityType: "document",
      entityId: "document_acme_policy",
      result: "success"
    });
  });

  it("allows auditors to view tenant audit events without transport metadata", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const ownerCookie = await login(app, "owner@acme.test");
    const auditorCookie = await login(app, "auditor@acme.test");

    await app.inject({
      method: "DELETE",
      url: "/documents/document_acme_policy",
      headers: { cookie: ownerCookie, "x-tenant-id": "tenant_acme" }
    });

    const response = await app.inject({
      method: "GET",
      url: "/audit-events",
      headers: { cookie: auditorCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().auditEvents).toEqual([
      expect.objectContaining({
        tenantId: "tenant_acme",
        actorType: "user",
        action: "document.deleted",
        entityType: "document",
        entityId: "document_acme_policy",
        result: "success"
      })
    ]);
    expect(response.json().auditEvents[0]).not.toHaveProperty("ipHash");
    expect(response.json().auditEvents[0]).not.toHaveProperty("userAgent");
  });

  it("denies audit event reads for members", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "GET",
      url: "/audit-events",
      headers: { cookie, "x-tenant-id": "tenant_acme" }
    });

    expect(response.statusCode).toBe(403);
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "authorization.denied",
      entityType: "audit_event",
      result: "failure",
      metadata: expect.objectContaining({
        requestedAction: "audit:read"
      })
    });
  });

  it("denies document version uploads for viewers", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "viewer@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/documents/document_acme_policy/versions",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: pdfUploadPayload()
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
  });

  it("rejects forbidden upload extensions", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/documents/document_acme_policy/versions",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        ...pdfUploadPayload(),
        originalFilename: "payload.exe"
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "extension_not_allowed" });
  });

  it("rejects upload content with mismatched file signature", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/documents/document_acme_policy/versions",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: {
        ...pdfUploadPayload(),
        contentBase64: Buffer.from([0xff, 0xd8, 0xff, 0x00, 0x00]).toString("base64")
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "file_signature_mismatch" });
  });

  it("stores uploaded versions as pending scan and blocks download until clean", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const cookie = await login(app, "member@acme.test");

    const upload = await app.inject({
      method: "POST",
      url: "/documents/document_acme_policy/versions",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: pdfUploadPayload()
    });

    expect(upload.statusCode).toBe(201);
    expect(upload.json().version).toMatchObject({
      documentId: "document_acme_policy",
      originalFilename: "evidence.pdf",
      mimeType: "application/pdf",
      scanStatus: "pending_scan"
    });
    expect(upload.json().version).not.toHaveProperty("storageKey");
    expect(store.scanJobs).toHaveLength(1);
    expect(store.scanJobs[0]).toMatchObject({
      tenantId: "tenant_acme",
      documentId: "document_acme_policy",
      versionId: upload.json().version.id,
      status: "queued"
    });
    expect(store.auditEvents.map((event) => event.action)).toEqual(
      expect.arrayContaining(["document.uploaded", "document.scan_queued"])
    );

    const download = await app.inject({
      method: "GET",
      url: "/documents/document_acme_policy/download",
      headers: { cookie, "x-tenant-id": "tenant_acme" }
    });

    expect(download.statusCode).toBe(409);
    expect(download.json()).toEqual({ error: "file_not_available_until_clean_scan" });
  });

  it("allows download metadata after a clean scan without exposing storage path", async () => {
    const app = buildApp({ store: createDemoStore() });
    const memberCookie = await login(app, "member@acme.test");
    const adminCookie = await login(app, "admin@acme.test");

    const upload = await app.inject({
      method: "POST",
      url: "/documents/document_acme_policy/versions",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" },
      payload: pdfUploadPayload()
    });
    const versionId = upload.json().version.id;

    const scan = await app.inject({
      method: "POST",
      url: `/document-versions/${versionId}/scan-result`,
      headers: { cookie: adminCookie, "x-tenant-id": "tenant_acme" },
      payload: { scanStatus: "clean" }
    });

    expect(scan.statusCode).toBe(200);

    const download = await app.inject({
      method: "GET",
      url: "/documents/document_acme_policy/download",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(download.statusCode).toBe(200);
    expect(download.json().download).toMatchObject({
      documentId: "document_acme_policy",
      versionId,
      originalFilename: "evidence.pdf",
      mimeType: "application/pdf",
      expiresInSeconds: 300
    });
    expect(download.json().download).not.toHaveProperty("storageKey");
    expect(download.json().download).not.toHaveProperty("storagePath");
  });

  it("keeps blocked files unavailable for download", async () => {
    const app = buildApp({ store: createDemoStore() });
    const memberCookie = await login(app, "member@acme.test");
    const adminCookie = await login(app, "admin@acme.test");

    const upload = await app.inject({
      method: "POST",
      url: "/documents/document_acme_policy/versions",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" },
      payload: pdfUploadPayload()
    });
    const versionId = upload.json().version.id;

    await app.inject({
      method: "POST",
      url: `/document-versions/${versionId}/scan-result`,
      headers: { cookie: adminCookie, "x-tenant-id": "tenant_acme" },
      payload: { scanStatus: "blocked" }
    });

    const download = await app.inject({
      method: "GET",
      url: "/documents/document_acme_policy/download",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(download.statusCode).toBe(409);
    expect(download.json()).toEqual({ error: "file_not_available_until_clean_scan" });
  });

  it("processes the queued scan job and transitions clean files to downloadable", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const memberCookie = await login(app, "member@acme.test");
    const adminCookie = await login(app, "admin@acme.test");

    const upload = await app.inject({
      method: "POST",
      url: "/documents/document_acme_policy/versions",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" },
      payload: pdfUploadPayload()
    });
    const versionId = upload.json().version.id;

    const scanJob = await app.inject({
      method: "POST",
      url: "/internal/scan-jobs/process-next",
      headers: { cookie: adminCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(scanJob.statusCode).toBe(200);
    expect(scanJob.json().scanJob).toMatchObject({
      tenantId: "tenant_acme",
      documentId: "document_acme_policy",
      versionId,
      status: "completed",
      attempts: 1
    });
    expect(store.documentVersions.find((version) => version.id === versionId)?.scanStatus).toBe(
      "clean"
    );
    expect(store.auditEvents.map((event) => event.action)).toEqual(
      expect.arrayContaining(["document.scan_clean"])
    );

    const download = await app.inject({
      method: "GET",
      url: "/documents/document_acme_policy/download",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(download.statusCode).toBe(200);
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "document.downloaded",
      entityType: "document_version",
      entityId: versionId,
      result: "success"
    });
    expect(download.json().download).toMatchObject({
      documentId: "document_acme_policy",
      versionId,
      originalFilename: "evidence.pdf",
      expiresInSeconds: 300
    });
    expect(download.json().download).toHaveProperty("expiresAt");
    expect(download.json().download).not.toHaveProperty("storageKey");
  });

  it("processes the queued scan job and keeps malware-demo files blocked", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const memberCookie = await login(app, "member@acme.test");
    const adminCookie = await login(app, "admin@acme.test");

    const upload = await app.inject({
      method: "POST",
      url: "/documents/document_acme_policy/versions",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" },
      payload: pdfUploadPayload("malware-demo")
    });
    const versionId = upload.json().version.id;

    const scanJob = await app.inject({
      method: "POST",
      url: "/internal/scan-jobs/process-next",
      headers: { cookie: adminCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(scanJob.statusCode).toBe(200);
    expect(store.documentVersions.find((version) => version.id === versionId)?.scanStatus).toBe(
      "blocked"
    );
    expect(store.auditEvents.map((event) => event.action)).toEqual(
      expect.arrayContaining(["document.scan_blocked"])
    );

    const download = await app.inject({
      method: "GET",
      url: "/documents/document_acme_policy/download",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(download.statusCode).toBe(409);
  });

  it("runs the project document upload scan lifecycle and exposes generated audit events", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const ownerCookie = await login(app, "owner@acme.test");

    const projectResponse = await app.inject({
      method: "POST",
      url: "/projects",
      headers: { cookie: ownerCookie, "x-tenant-id": "tenant_acme" },
      payload: {
        name: "Lifecycle Evidence",
        classification: "internal"
      }
    });
    const projectId = projectResponse.json().project.id;

    const documentResponse = await app.inject({
      method: "POST",
      url: "/documents",
      headers: { cookie: ownerCookie, "x-tenant-id": "tenant_acme" },
      payload: {
        title: "Lifecycle Report",
        projectId,
        classification: "confidential"
      }
    });
    const documentId = documentResponse.json().document.id;

    await app.inject({
      method: "POST",
      url: `/documents/${documentId}/versions`,
      headers: { cookie: ownerCookie, "x-tenant-id": "tenant_acme" },
      payload: pdfUploadPayload()
    });
    await app.inject({
      method: "POST",
      url: "/internal/scan-jobs/process-next",
      headers: { cookie: ownerCookie, "x-tenant-id": "tenant_acme" }
    });

    const auditResponse = await app.inject({
      method: "GET",
      url: "/audit-events",
      headers: { cookie: ownerCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(auditResponse.statusCode).toBe(200);
    expect(auditResponse.json().auditEvents.map((event: { action: string }) => event.action)).toEqual(
      expect.arrayContaining([
        "project.created",
        "document.created",
        "document.uploaded",
        "document.scan_queued",
        "document.scan_clean"
      ])
    );
  });

  it("creates share links with one-time tokens and stores only token hashes", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const memberCookie = await login(app, "member@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/share-links",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" },
      payload: {
        documentId: "document_acme_policy",
        expiresInMinutes: 30,
        maxDownloads: 2
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json().shareToken).toEqual(expect.stringMatching(/^tv_share_/));
    expect(response.json().shareLink).toMatchObject({
      tenantId: "tenant_acme",
      documentId: "document_acme_policy",
      permission: "download",
      maxDownloads: 2,
      downloadCount: 0
    });
    expect(response.json().shareLink).not.toHaveProperty("tokenHash");
    expect(store.shareLinks[0]?.tokenHash).not.toBe(response.json().shareToken);
    expect(JSON.stringify(store.auditEvents)).not.toContain(response.json().shareToken);
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "share_link.created",
      entityType: "share_link",
      result: "success"
    });
  });

  it("allows public share link download and increments max download counters", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const memberCookie = await login(app, "member@acme.test");

    const created = await app.inject({
      method: "POST",
      url: "/share-links",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" },
      payload: {
        documentId: "document_acme_policy",
        maxDownloads: 1
      }
    });
    const token = created.json().shareToken;

    const firstUse = await app.inject({
      method: "GET",
      url: `/public/share-links/${token}`
    });

    expect(firstUse.statusCode).toBe(200);
    expect(firstUse.json().download).toMatchObject({
      documentId: "document_acme_policy",
      originalFilename: "security-policy.pdf",
      expiresInSeconds: 300
    });
    expect(firstUse.json().download).not.toHaveProperty("storageKey");
    expect(firstUse.json().shareLink.downloadCount).toBe(1);
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "share_link.used",
      entityType: "share_link",
      result: "success"
    });

    const secondUse = await app.inject({
      method: "GET",
      url: `/public/share-links/${token}`
    });

    expect(secondUse.statusCode).toBe(403);
    expect(secondUse.json()).toEqual({ error: "share_link_download_limit_reached" });
  });

  it("rejects invalid expired and revoked share links", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const memberCookie = await login(app, "member@acme.test");

    const invalid = await app.inject({
      method: "GET",
      url: "/public/share-links/tv_share_invalid"
    });

    expect(invalid.statusCode).toBe(404);

    const expired = await app.inject({
      method: "POST",
      url: "/share-links",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" },
      payload: {
        documentId: "document_acme_policy",
        expiresInMinutes: 1
      }
    });
    store.shareLinks[0]!.expiresAt = new Date(Date.now() - 1000);

    const expiredUse = await app.inject({
      method: "GET",
      url: `/public/share-links/${expired.json().shareToken}`
    });

    expect(expiredUse.statusCode).toBe(410);
    expect(expiredUse.json()).toEqual({ error: "share_link_expired" });

    const active = await app.inject({
      method: "POST",
      url: "/share-links",
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" },
      payload: {
        documentId: "document_acme_policy"
      }
    });

    const revoke = await app.inject({
      method: "DELETE",
      url: `/share-links/${active.json().shareLink.id}`,
      headers: { cookie: memberCookie, "x-tenant-id": "tenant_acme" }
    });

    expect(revoke.statusCode).toBe(200);

    const revokedUse = await app.inject({
      method: "GET",
      url: `/public/share-links/${active.json().shareToken}`
    });

    expect(revokedUse.statusCode).toBe(403);
    expect(revokedUse.json()).toEqual({ error: "share_link_revoked" });
  });

  it("denies share link creation for viewers", async () => {
    const store = createDemoStore();
    const app = buildApp({ store });
    const viewerCookie = await login(app, "viewer@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/share-links",
      headers: { cookie: viewerCookie, "x-tenant-id": "tenant_acme" },
      payload: {
        documentId: "document_acme_policy"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(store.auditEvents.at(-1)).toMatchObject({
      action: "authorization.denied",
      entityType: "document",
      result: "failure",
      metadata: expect.objectContaining({
        requestedAction: "documents:update"
      })
    });
  });
});

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

function pdfUploadPayload(marker = "") {
  const content = Buffer.from(`%PDF-${marker}`);

  return {
    originalFilename: "evidence.pdf",
    mimeType: "application/pdf",
    sizeBytes: content.byteLength,
    contentBase64: content.toString("base64")
  };
}
