import type { FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import type { AppStore, Membership, Session, Tenant, User } from "./domain.js";
import { readCookie, sessionCookieName } from "./http.js";

export type AuthenticatedRequestContext = {
  user: User;
  session: Session;
};

export type TenantRequestContext = AuthenticatedRequestContext & {
  tenant: Tenant;
  membership: Membership;
};

declare module "fastify" {
  interface FastifyRequest {
    auth?: AuthenticatedRequestContext;
    tenantContext?: TenantRequestContext;
  }
}

export function createSession(store: AppStore, userId: string): Session {
  const session: Session = {
    id: `sess_${randomUUID()}`,
    userId,
    createdAt: new Date()
  };

  store.sessions.push(session);

  return session;
}

export function revokeSession(store: AppStore, sessionId: string): boolean {
  const session = store.sessions.find((candidate) => candidate.id === sessionId);

  if (!session || session.revokedAt) {
    return false;
  }

  session.revokedAt = new Date();

  return true;
}

export function authenticateRequest(
  store: AppStore,
  request: FastifyRequest
): AuthenticatedRequestContext | undefined {
  const sessionId = readCookie(request, sessionCookieName);

  if (!sessionId) {
    return undefined;
  }

  const session = store.sessions.find(
    (candidate) => candidate.id === sessionId && !candidate.revokedAt
  );

  if (!session) {
    return undefined;
  }

  const user = store.users.find(
    (candidate) => candidate.id === session.userId && candidate.status === "active"
  );

  if (!user) {
    return undefined;
  }

  return { user, session };
}

export async function requireAuth(
  store: AppStore,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const auth = authenticateRequest(store, request);

  if (!auth) {
    await reply.code(401).send({ error: "unauthorized" });
    return;
  }

  request.auth = auth;
}

export async function requireTenantContext(
  store: AppStore,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  await requireAuth(store, request, reply);

  if (!request.auth) {
    return;
  }

  const tenantId = request.headers["x-tenant-id"];

  if (typeof tenantId !== "string") {
    await reply.code(400).send({ error: "tenant_required" });
    return;
  }

  const membership = store.memberships.find(
    (candidate) =>
      candidate.tenantId === tenantId &&
      candidate.userId === request.auth?.user.id &&
      candidate.status === "active"
  );

  if (!membership) {
    await reply.code(403).send({ error: "tenant_membership_required" });
    return;
  }

  const tenant = store.tenants.find((candidate) => candidate.id === tenantId);

  if (!tenant) {
    await reply.code(403).send({ error: "tenant_membership_required" });
    return;
  }

  request.tenantContext = {
    ...request.auth,
    tenant,
    membership
  };
}

