export const roles = [
  "owner",
  "admin",
  "member",
  "viewer",
  "auditor",
  "support_operator"
] as const;

export type Role = (typeof roles)[number];

export type Permission =
  | "tenant:update"
  | "members:invite"
  | "members:update_role"
  | "documents:create"
  | "documents:read"
  | "documents:update"
  | "documents:delete"
  | "documents:*"
  | "audit:read"
  | "api_keys:create"
  | "api_keys:read"
  | "api_keys:revoke"
  | "api_keys:*"
  | "security:read"
  | "support_access:request"
  | "support_access:approve"
  | "support_access:use";

export type Action = Exclude<Permission, `${string}:*`>;

export type MembershipStatus = "active" | "invited" | "suspended";

export type Actor = {
  id: string;
  tenantId: string;
  role: Role;
  membershipStatus: MembershipStatus;
  projectIds?: readonly string[];
};

export type Resource = {
  tenantId: string;
  projectId?: string;
  ownerId?: string;
  classification?: "public" | "internal" | "confidential" | "restricted";
};

export type AuthorizationDecision = {
  allowed: boolean;
  reason?: string;
};

export const permissionsByRole: Record<Role, readonly Permission[]> = {
  owner: [
    "tenant:update",
    "members:invite",
    "members:update_role",
    "documents:*",
    "audit:read",
    "api_keys:*",
    "security:read",
    "support_access:approve"
  ],
  admin: [
    "members:invite",
    "members:update_role",
    "documents:*",
    "audit:read",
    "api_keys:read",
    "security:read"
  ],
  member: ["documents:create", "documents:read", "documents:update"],
  viewer: ["documents:read"],
  auditor: ["documents:read", "audit:read", "security:read"],
  support_operator: ["support_access:request", "support_access:use"]
};

export function can(
  actor: Actor,
  action: Action,
  resource?: Resource
): AuthorizationDecision {
  if (actor.membershipStatus !== "active") {
    return deny("membership_not_active");
  }

  if (resource && actor.tenantId !== resource.tenantId) {
    return deny("tenant_mismatch");
  }

  if (!roleAllows(actor.role, action)) {
    return deny("permission_missing");
  }

  if (resource?.projectId && !hasProjectAccess(actor, resource.projectId)) {
    return deny("project_access_missing");
  }

  if (
    resource?.classification === "restricted" &&
    actor.role !== "owner" &&
    actor.role !== "admin" &&
    actor.role !== "auditor"
  ) {
    return deny("restricted_resource");
  }

  return { allowed: true };
}

export function requireAllowed(decision: AuthorizationDecision): void {
  if (!decision.allowed) {
    throw new AuthorizationError(decision.reason ?? "access_denied");
  }
}

export class AuthorizationError extends Error {
  constructor(public readonly reason: string) {
    super(`Access denied: ${reason}`);
    this.name = "AuthorizationError";
  }
}

export function roleAllows(role: Role, action: Action): boolean {
  return permissionsByRole[role].some((permission) =>
    permission === action || matchesWildcard(permission, action)
  );
}

function matchesWildcard(permission: Permission, action: Action): boolean {
  if (!permission.endsWith(":*")) {
    return false;
  }

  const [permissionArea] = permission.split(":");
  const [actionArea] = action.split(":");

  return permissionArea === actionArea;
}

function hasProjectAccess(actor: Actor, projectId: string): boolean {
  if (actor.role === "owner" || actor.role === "admin" || actor.role === "auditor") {
    return true;
  }

  return actor.projectIds?.includes(projectId) ?? false;
}

function deny(reason: string): AuthorizationDecision {
  return { allowed: false, reason };
}
