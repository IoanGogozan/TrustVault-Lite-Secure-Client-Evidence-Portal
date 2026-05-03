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

  it("allows owners to invite a new member", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "owner@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/tenant/invitations",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { email: "auditor@acme.test", role: "auditor" }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({
      invitation: {
        tenantId: "tenant_acme",
        email: "auditor@acme.test",
        role: "auditor",
        status: "pending"
      }
    });
    expect(response.json().inviteToken).toEqual(expect.stringMatching(/^invite_/));
  });

  it("denies invitation creation for viewers", async () => {
    const app = buildApp({ store: createDemoStore() });
    const cookie = await login(app, "viewer@acme.test");

    const response = await app.inject({
      method: "POST",
      url: "/tenant/invitations",
      headers: { cookie, "x-tenant-id": "tenant_acme" },
      payload: { email: "new-viewer@acme.test", role: "viewer" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "permission_denied" });
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
