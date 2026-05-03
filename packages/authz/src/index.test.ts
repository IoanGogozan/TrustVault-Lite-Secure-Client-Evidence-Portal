import { describe, expect, it } from "vitest";
import {
  AuthorizationError,
  type Actor,
  can,
  requireAllowed,
  roleAllows
} from "./index.js";

const activeMember: Actor = {
  id: "user_1",
  tenantId: "tenant_a",
  role: "member",
  membershipStatus: "active",
  projectIds: ["project_1"]
};

describe("roleAllows", () => {
  it("supports wildcard permissions only within the same area", () => {
    expect(roleAllows("owner", "documents:delete")).toBe(true);
    expect(roleAllows("owner", "api_keys:revoke")).toBe(true);
    expect(roleAllows("viewer", "documents:read")).toBe(true);
    expect(roleAllows("viewer", "documents:create")).toBe(false);
  });
});

describe("can", () => {
  it("denies by default when permission is missing", () => {
    const decision = can(
      { ...activeMember, role: "viewer" },
      "documents:create",
      { tenantId: "tenant_a", projectId: "project_1" }
    );

    expect(decision).toEqual({
      allowed: false,
      reason: "permission_missing"
    });
  });

  it("denies actors without active membership", () => {
    const decision = can(
      { ...activeMember, membershipStatus: "suspended" },
      "documents:read",
      { tenantId: "tenant_a", projectId: "project_1" }
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("membership_not_active");
  });

  it("denies cross-tenant resource access", () => {
    const decision = can(activeMember, "documents:read", {
      tenantId: "tenant_b",
      projectId: "project_1"
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("tenant_mismatch");
  });

  it("denies project access for members outside the project", () => {
    const decision = can(activeMember, "documents:read", {
      tenantId: "tenant_a",
      projectId: "project_2"
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("project_access_missing");
  });

  it("allows a member to read a document in their tenant and project", () => {
    const decision = can(activeMember, "documents:read", {
      tenantId: "tenant_a",
      projectId: "project_1"
    });

    expect(decision.allowed).toBe(true);
  });

  it("denies restricted documents to normal members", () => {
    const decision = can(activeMember, "documents:read", {
      tenantId: "tenant_a",
      projectId: "project_1",
      classification: "restricted"
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("restricted_resource");
  });

  it("allows auditors to read restricted documents", () => {
    const decision = can(
      { ...activeMember, role: "auditor", projectIds: [] },
      "documents:read",
      {
        tenantId: "tenant_a",
        projectId: "project_2",
        classification: "restricted"
      }
    );

    expect(decision.allowed).toBe(true);
  });
});

describe("requireAllowed", () => {
  it("throws an authorization error for denied decisions", () => {
    expect(() =>
      requireAllowed({ allowed: false, reason: "tenant_mismatch" })
    ).toThrow(AuthorizationError);
  });
});

