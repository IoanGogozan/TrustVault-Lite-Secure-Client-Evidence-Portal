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

