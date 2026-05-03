import Fastify, { type FastifyInstance } from "fastify";
import { readBaseConfig } from "@trustvault/config";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  createSession,
  requireAuth,
  requireTenantContext,
  revokeSession,
  type TenantRequestContext
} from "./auth.js";
import {
  createDemoStore,
  type AppStore,
  type DocumentClassification,
  type MembershipRole,
  type User
} from "./domain.js";
import { clearSessionCookie, setSessionCookie } from "./http.js";
import { requirePermission } from "./authorization.js";
import {
  InMemoryDocumentRepository,
  type DocumentReadScope,
  type DocumentRepository
} from "./documents.js";

export type BuildAppOptions = {
  store?: AppStore;
  documentRepository?: DocumentRepository;
};

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const config = readBaseConfig();
  const store = options.store ?? createDemoStore();
  const documentRepository = options.documentRepository ?? new InMemoryDocumentRepository(store);
  const app = Fastify({
    logger: config.env === "production"
  });

  app.addHook("onRequest", async (request, reply) => {
    const origin = request.headers.origin;

    if (origin && isAllowedOrigin(origin)) {
      reply.header("Access-Control-Allow-Origin", origin);
      reply.header("Access-Control-Allow-Credentials", "true");
      reply.header("Vary", "Origin");
    }
  });

  app.options("*", async (request, reply) => {
    const origin = request.headers.origin;

    if (!origin || !isAllowedOrigin(origin)) {
      return reply.code(403).send({ error: "origin_not_allowed" });
    }

    return reply
      .header("Access-Control-Allow-Origin", origin)
      .header("Access-Control-Allow-Credentials", "true")
      .header("Access-Control-Allow-Headers", "Content-Type, X-Tenant-Id")
      .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
      .header("Vary", "Origin")
      .code(204)
      .send();
  });

  app.get("/health", async () => ({ status: "ok", app: config.appName }));

  app.post<{ Body: { email?: string } }>("/auth/dev-login", async (request, reply) => {
    if (config.env === "production") {
      return reply.code(404).send({ error: "not_found" });
    }

    const user = store.users.find((candidate) => candidate.email === request.body.email);

    if (!user) {
      return reply.code(401).send({ error: "invalid_credentials" });
    }

    const session = createSession(store, user.id);
    setSessionCookie(reply, session.id);

    return reply.code(204).send();
  });

  app.post("/auth/logout", async (request, reply) => {
    await requireAuth(store, request, reply);

    if (!request.auth) {
      return;
    }

    revokeSession(store, request.auth.session.id);
    clearSessionCookie(reply);

    return reply.code(204).send();
  });

  app.get("/me", async (request, reply) => {
    await requireAuth(store, request, reply);

    if (!request.auth) {
      return;
    }

    const memberships = store.memberships
      .filter(
        (membership) =>
          membership.userId === request.auth?.user.id && membership.status === "active"
      )
      .map((membership) => {
        const tenant = store.tenants.find((candidate) => candidate.id === membership.tenantId);

        return {
          tenantId: membership.tenantId,
          tenantName: tenant?.name,
          tenantSlug: tenant?.slug,
          role: membership.role,
          mfaRequired: membership.mfaRequired
        };
      });

    return {
      user: {
        id: request.auth.user.id,
        email: request.auth.user.email,
        name: request.auth.user.name
      },
      memberships
    };
  });

  app.post<{ Body: { name?: string; slug?: string } }>("/tenants", async (request, reply) => {
    await requireAuth(store, request, reply);

    if (!request.auth) {
      return;
    }

    const name = normalizeName(request.body.name);

    if (!name) {
      return reply.code(400).send({ error: "tenant_name_required" });
    }

    const slug = normalizeSlug(request.body.slug ?? name);

    if (!slug) {
      return reply.code(400).send({ error: "tenant_slug_required" });
    }

    if (store.tenants.some((tenant) => tenant.slug === slug)) {
      return reply.code(409).send({ error: "tenant_slug_taken" });
    }

    const tenant = {
      id: `tenant_${randomUUID()}`,
      name,
      slug,
      plan: "demo" as const,
      createdAt: new Date()
    };

    store.tenants.push(tenant);
    store.memberships.push({
      id: `membership_${randomUUID()}`,
      tenantId: tenant.id,
      userId: request.auth.user.id,
      role: "owner",
      status: "active",
      mfaRequired: true,
      createdAt: new Date()
    });

    return reply.code(201).send({
      tenant: {
        id: tenant.id,
        name: tenant.name,
        slug: tenant.slug,
        plan: tenant.plan
      }
    });
  });

  app.get("/tenant/current", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    return {
      tenant: {
        id: request.tenantContext.tenant.id,
        name: request.tenantContext.tenant.name,
        slug: request.tenantContext.tenant.slug,
        plan: request.tenantContext.tenant.plan
      },
      membership: {
        role: request.tenantContext.membership.role,
        mfaRequired: request.tenantContext.membership.mfaRequired
      }
    };
  });

  app.patch<{
    Params: { membershipId: string };
    Body: { role?: MembershipRole };
  }>("/memberships/:membershipId/role", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const targetMembership = store.memberships.find(
      (membership) =>
        membership.id === request.params.membershipId &&
        membership.tenantId === request.tenantContext?.tenant.id &&
        membership.status === "active"
    );

    if (!targetMembership) {
      return reply.code(404).send({ error: "membership_not_found" });
    }

    const nextRole = request.body.role;

    if (!nextRole || !isAssignableRole(nextRole)) {
      return reply.code(400).send({ error: "invalid_role" });
    }

    const allowed = await requirePermission(store, request, reply, "members:update_role", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "membership",
      entityId: targetMembership.id
    });

    if (!allowed) {
      return;
    }

    const roleChangeDecision = canChangeMembershipRole(
      request.tenantContext.membership.role,
      targetMembership.role,
      nextRole
    );

    if (!roleChangeDecision.allowed) {
      await denyMembershipRoleChange(
        store,
        request,
        reply,
        targetMembership.id,
        roleChangeDecision.reason
      );
      return;
    }

    targetMembership.role = nextRole;

    return {
      membership: {
        id: targetMembership.id,
        tenantId: targetMembership.tenantId,
        userId: targetMembership.userId,
        role: targetMembership.role,
        status: targetMembership.status
      }
    };
  });

  app.post<{
    Body: { email?: string; role?: MembershipRole };
  }>("/tenant/invitations", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const allowed = await requirePermission(store, request, reply, "members:invite", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "invitation"
    });

    if (!allowed) {
      return;
    }

    const email = normalizeEmail(request.body.email);
    const role = request.body.role;

    if (!email) {
      return reply.code(400).send({ error: "email_required" });
    }

    if (!role || !isInvitableRole(role)) {
      return reply.code(400).send({ error: "invalid_role" });
    }

    const existingMembership = store.memberships.find((membership) => {
      const user = store.users.find((candidate) => candidate.id === membership.userId);

      return (
        membership.tenantId === request.tenantContext?.tenant.id &&
        user?.email === email &&
        membership.status !== "suspended"
      );
    });

    if (existingMembership) {
      return reply.code(409).send({ error: "membership_already_exists" });
    }

    const token = `invite_${randomBytes(24).toString("base64url")}`;
    const invitation = {
      id: `invite_${randomUUID()}`,
      tenantId: request.tenantContext.tenant.id,
      email,
      role,
      tokenHash: hashSecret(token),
      status: "pending" as const,
      invitedBy: request.tenantContext.user.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      createdAt: new Date()
    };

    store.invitations.push(invitation);

    return reply.code(201).send({
      invitation: {
        id: invitation.id,
        tenantId: invitation.tenantId,
        email: invitation.email,
        role: invitation.role,
        status: invitation.status,
        expiresAt: invitation.expiresAt.toISOString()
      },
      inviteToken: token
    });
  });

  app.post<{
    Body: { token?: string; name?: string };
  }>("/invitations/accept", async (request, reply) => {
    const token = request.body.token;

    if (!token) {
      return reply.code(400).send({ error: "invite_token_required" });
    }

    const invitation = store.invitations.find(
      (candidate) =>
        candidate.tokenHash === hashSecret(token) &&
        candidate.status === "pending" &&
        candidate.expiresAt > new Date()
    );

    if (!invitation) {
      return reply.code(404).send({ error: "invite_not_found" });
    }

    const user = findOrCreateInvitedUser(store, invitation.email, request.body.name);

    store.memberships.push({
      id: `membership_${randomUUID()}`,
      tenantId: invitation.tenantId,
      userId: user.id,
      role: invitation.role,
      status: "active",
      mfaRequired: true,
      createdAt: new Date()
    });

    invitation.status = "accepted";
    invitation.acceptedBy = user.id;

    const session = createSession(store, user.id);
    setSessionCookie(reply, session.id);

    return reply.code(200).send({
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      },
      tenantId: invitation.tenantId,
      role: invitation.role
    });
  });

  app.get("/documents", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const allowed = await requirePermission(store, request, reply, "documents:read", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "document"
    });

    if (!allowed) {
      return;
    }

    return {
      documents: (await documentRepository.list(toDocumentReadScope(request.tenantContext))).map(
        toDocumentResponse
      )
    };
  });

  app.post<{
    Body: {
      title?: string;
      projectId?: string;
      classification?: DocumentClassification;
      tenantId?: string;
      storageKey?: string;
    };
  }>("/documents", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const title = normalizeName(request.body.title);
    const projectId = request.body.projectId;
    const classification = request.body.classification ?? "confidential";

    if (!title) {
      return reply.code(400).send({ error: "document_title_required" });
    }

    if (!projectId) {
      return reply.code(400).send({ error: "project_required" });
    }

    if (!isDocumentClassification(classification)) {
      return reply.code(400).send({ error: "invalid_classification" });
    }

    const project = store.projects.find((candidate) => candidate.id === projectId);

    if (!project) {
      return reply.code(404).send({ error: "project_not_found" });
    }

    const allowed = await requirePermission(store, request, reply, "documents:create", {
      tenantId: project.tenantId,
      projectId: project.id,
      classification,
      entityType: "document"
    });

    if (!allowed) {
      return;
    }

    const document = await documentRepository.create({
      tenantId: request.tenantContext.tenant.id,
      projectId: project.id,
      title,
      classification,
      createdBy: request.tenantContext.user.id
    });

    return reply.code(201).send({ document: toDocumentResponse(document) });
  });

  app.get<{ Params: { documentId: string } }>("/documents/:documentId", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const document =
      (await documentRepository.findByIdForAuthorization?.(request.params.documentId)) ??
      (await documentRepository.findVisibleById(
      toDocumentReadScope(request.tenantContext),
      request.params.documentId
      ));

    if (!document) {
      return reply.code(404).send({ error: "document_not_found" });
    }

    const allowed = await requirePermission(store, request, reply, "documents:read", {
      tenantId: document.tenantId,
      projectId: document.projectId,
      classification: document.classification,
      entityType: "document",
      entityId: document.id
    });

    if (!allowed) {
      return;
    }

    return { document: toDocumentResponse(document) };
  });

  app.delete<{ Params: { documentId: string } }>(
    "/documents/:documentId",
    async (request, reply) => {
      await requireTenantContext(store, request, reply);

      if (!request.tenantContext) {
        return;
      }

      const document =
        (await documentRepository.findByIdForAuthorization?.(request.params.documentId)) ??
        (await documentRepository.findVisibleById(
        toDocumentReadScope(request.tenantContext),
        request.params.documentId
        ));

      if (!document) {
        return reply.code(404).send({ error: "document_not_found" });
      }

      const allowed = await requirePermission(store, request, reply, "documents:delete", {
        tenantId: document.tenantId,
        projectId: document.projectId,
        classification: document.classification,
        entityType: "document",
        entityId: document.id
      });

      if (!allowed) {
        return;
      }

      await documentRepository.softDelete(
        toDocumentReadScope(request.tenantContext),
        request.params.documentId
      );

      return reply.code(204).send();
    }
  );

  return app;
}

function normalizeName(name: string | undefined): string | undefined {
  const normalized = name?.trim().replace(/\s+/g, " ");

  return normalized || undefined;
}

function normalizeEmail(email: string | undefined): string | undefined {
  const normalized = email?.trim().toLowerCase();

  return normalized && normalized.includes("@") ? normalized : undefined;
}

function normalizeSlug(value: string): string | undefined {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return slug || undefined;
}

function isInvitableRole(role: string): role is MembershipRole {
  return role === "admin" || role === "member" || role === "viewer" || role === "auditor";
}

function isAssignableRole(role: string): role is MembershipRole {
  return role === "owner" || role === "admin" || role === "member" || role === "viewer" || role === "auditor";
}

function canChangeMembershipRole(
  actorRole: MembershipRole,
  targetRole: MembershipRole,
  nextRole: MembershipRole
): { allowed: true } | { allowed: false; reason: string } {
  if (actorRole !== "owner" && actorRole !== "admin") {
    return { allowed: false, reason: "permission_missing" };
  }

  if (actorRole === "admin" && (targetRole === "owner" || nextRole === "owner")) {
    return { allowed: false, reason: "owner_role_protected" };
  }

  if (actorRole !== "owner" && targetRole === "owner") {
    return { allowed: false, reason: "owner_role_protected" };
  }

  return { allowed: true };
}

async function denyMembershipRoleChange(
  store: AppStore,
  request: Parameters<typeof requirePermission>[1],
  reply: Parameters<typeof requirePermission>[2],
  membershipId: string,
  reason: string
): Promise<void> {
  if (!request.tenantContext) {
    await reply.code(500).send({ error: "tenant_context_required" });
    return;
  }

  store.auditEvents.push({
    id: `audit_${randomUUID()}`,
    tenantId: request.tenantContext.tenant.id,
    actorUserId: request.tenantContext.user.id,
    actorType: "user",
    action: "authorization.denied",
    entityType: "membership",
    entityId: membershipId,
    result: "failure",
    ipHash: hashSecret(request.ip),
    userAgent: request.headers["user-agent"] ?? "unknown",
    metadata: {
      requestedAction: "members:update_role",
      reason
    },
    createdAt: new Date()
  });

  await reply.code(403).send({ error: "permission_denied" });
}

function isDocumentClassification(value: string): value is DocumentClassification {
  return (
    value === "public" ||
    value === "internal" ||
    value === "confidential" ||
    value === "restricted"
  );
}

function toDocumentResponse(document: {
  id: string;
  tenantId: string;
  projectId: string;
  title: string;
  classification: DocumentClassification;
  createdBy: string;
  createdAt: Date;
}) {
  return {
    id: document.id,
    tenantId: document.tenantId,
    projectId: document.projectId,
    title: document.title,
    classification: document.classification,
    createdBy: document.createdBy,
    createdAt: document.createdAt.toISOString()
  };
}

function toDocumentReadScope(context: TenantRequestContext): DocumentReadScope {
  return {
    tenantId: context.tenant.id,
    role: context.membership.role,
    ...(context.membership.projectIds ? { projectIds: context.membership.projectIds } : {})
  };
}

function hashSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

function findOrCreateInvitedUser(
  store: AppStore,
  email: string,
  name: string | undefined
): User {
  const existingUser = store.users.find((user) => user.email === email);

  if (existingUser) {
    return existingUser;
  }

  const user = {
    id: `user_${randomUUID()}`,
    email,
    name: normalizeName(name) ?? email.split("@")[0] ?? "Invited User",
    identityProviderSubject: `demo-invite|${email}`,
    status: "active" as const,
    createdAt: new Date()
  };

  store.users.push(user);

  return user;
}

function isAllowedOrigin(origin: string): boolean {
  return origin === "http://localhost:3000" || origin === "http://127.0.0.1:3000";
}
