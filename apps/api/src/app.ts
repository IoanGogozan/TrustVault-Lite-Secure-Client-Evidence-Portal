import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { redactAuditMetadata, type AuditActorType, type AuditResult } from "@trustvault/audit";
import { readBaseConfig } from "@trustvault/config";
import { InMemoryPrivateObjectStorage, type PrivateObjectStorage } from "@trustvault/storage";
import { validateDocumentUpload } from "@trustvault/validation";
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
  type ApiKey,
  type ApiKeyScope,
  type AppStore,
  type DocumentClassification,
  type MembershipRole,
  type User
} from "./domain.js";
import { clearSessionCookie, csrfCookieName, readCookie, sessionCookieName, setSessionCookie } from "./http.js";
import { requirePermission } from "./authorization.js";
import {
  InMemoryDocumentRepository,
  type DocumentReadScope,
  type DocumentRepository
} from "./documents.js";
import {
  InMemoryProjectRepository,
  type ProjectReadScope,
  type ProjectRepository
} from "./projects.js";
import { InMemoryScanJobQueue, type ScanJobQueue } from "./scan-worker.js";
import {
  InMemoryShareLinkRepository,
  type ShareLinkRepository
} from "./share-links.js";
import {
  InMemoryApiKeyRepository,
  type ApiKeyRepository
} from "./api-keys.js";
import {
  InMemoryRateLimiter,
  type RateLimiter,
  type RateLimitRule
} from "./rate-limiter.js";

export type BuildAppOptions = {
  store?: AppStore;
  documentRepository?: DocumentRepository;
  projectRepository?: ProjectRepository;
  shareLinkRepository?: ShareLinkRepository;
  apiKeyRepository?: ApiKeyRepository;
  scanQueue?: ScanJobQueue;
  storage?: PrivateObjectStorage;
  rateLimiter?: RateLimiter;
};

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const config = readBaseConfig();
  const store = options.store ?? createDemoStore();
  const documentRepository = options.documentRepository ?? new InMemoryDocumentRepository(store);
  const projectRepository = options.projectRepository ?? new InMemoryProjectRepository(store);
  const shareLinkRepository =
    options.shareLinkRepository ?? new InMemoryShareLinkRepository(store);
  const apiKeyRepository = options.apiKeyRepository ?? new InMemoryApiKeyRepository(store);
  const storage = options.storage ?? new InMemoryPrivateObjectStorage(store.storageObjects);
  const scanQueue =
    options.scanQueue ?? new InMemoryScanJobQueue(store, documentRepository, storage);
  const rateLimiter = options.rateLimiter ?? new InMemoryRateLimiter();
  const app = Fastify({
    logger:
      config.env === "production"
        ? {
            redact: {
              paths: [
                "req.headers.authorization",
                "req.headers.cookie",
                "req.headers.x-csrf-token",
                "req.body.password",
                "req.body.token",
                "req.body.key",
                "req.body.apiKey",
                "req.body.contentBase64"
              ],
              censor: "[REDACTED]"
            }
          }
        : false,
    bodyLimit: 1_000_000
  });

  app.addHook("onRequest", async (request, reply) => {
    const origin = request.headers.origin;

    setSecurityHeaders(reply, config.env);

    if (origin && isAllowedOrigin(origin)) {
      reply.header("Access-Control-Allow-Origin", origin);
      reply.header("Access-Control-Allow-Credentials", "true");
      reply.header("Vary", "Origin");
    }

    const rateLimitResult = await applyRateLimit(rateLimiter, request);

    if (!rateLimitResult.allowed) {
      reply.header("Retry-After", Math.ceil(rateLimitResult.retryAfterMs / 1000).toString());
      return reply.code(429).send({ error: "rate_limit_exceeded" });
    }

    if (requiresCsrfCheck(request)) {
      const csrfCookie = readCookie(request, csrfCookieName);
      const csrfHeader = request.headers["x-csrf-token"];

      if (!csrfCookie || csrfHeader !== csrfCookie) {
        return reply.code(403).send({ error: "csrf_token_invalid" });
      }
    }
  });

  app.addHook("preValidation", async (request, reply) => {
    const validation = validateRequestShape(request);

    if (!validation.valid) {
      return reply.code(400).send({ error: validation.reason });
    }
  });

  app.setErrorHandler((error, _request, reply) => {
    const statusCode =
      typeof error === "object" &&
      error !== null &&
      "statusCode" in error &&
      typeof error.statusCode === "number" &&
      error.statusCode >= 400
        ? error.statusCode
        : 500;
    const errorCode =
      statusCode === 413
        ? "request_body_too_large"
        : statusCode >= 500
          ? "internal_server_error"
          : "bad_request";

    return reply.code(statusCode).send({ error: errorCode });
  });

  app.options("*", async (request, reply) => {
    const origin = request.headers.origin;

    if (!origin || !isAllowedOrigin(origin)) {
      return reply.code(403).send({ error: "origin_not_allowed" });
    }

    return reply
      .header("Access-Control-Allow-Origin", origin)
      .header("Access-Control-Allow-Credentials", "true")
      .header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token, X-Tenant-Id")
      .header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
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

  app.get("/projects", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const allowed = await requirePermission(store, request, reply, "projects:read", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "project"
    });

    if (!allowed) {
      return;
    }

    return {
      projects: (await projectRepository.list(toProjectReadScope(request.tenantContext))).map(
        toProjectResponse
      )
    };
  });

  app.post<{
    Body: {
      name?: string;
      classification?: DocumentClassification;
    };
  }>("/projects", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const name = normalizeName(request.body.name);
    const classification = request.body.classification ?? "confidential";

    if (!name) {
      return reply.code(400).send({ error: "project_name_required" });
    }

    if (!isDocumentClassification(classification)) {
      return reply.code(400).send({ error: "invalid_classification" });
    }

    const allowed = await requirePermission(store, request, reply, "projects:create", {
      tenantId: request.tenantContext.tenant.id,
      classification,
      entityType: "project"
    });

    if (!allowed) {
      return;
    }

    const project = await projectRepository.create({
      tenantId: request.tenantContext.tenant.id,
      name,
      classification,
      createdBy: request.tenantContext.user.id
    });
    appendAuditEvent(store, request, {
      action: "project.created",
      entityType: "project",
      entityId: project.id,
      result: "success",
      metadata: {
        classification: project.classification
      }
    });

    return reply.code(201).send({ project: toProjectResponse(project) });
  });

  app.patch<{
    Params: { projectId: string };
    Body: {
      name?: string;
      classification?: DocumentClassification;
    };
  }>("/projects/:projectId", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const project =
      (await projectRepository.findByIdForAuthorization?.(request.params.projectId)) ??
      (await projectRepository.findVisibleById(
        toProjectReadScope(request.tenantContext),
        request.params.projectId
      ));

    if (!project) {
      return reply.code(404).send({ error: "project_not_found" });
    }

    const name = request.body.name === undefined ? undefined : normalizeName(request.body.name);
    const classification = request.body.classification;

    if (request.body.name !== undefined && !name) {
      return reply.code(400).send({ error: "project_name_required" });
    }

    if (classification !== undefined && !isDocumentClassification(classification)) {
      return reply.code(400).send({ error: "invalid_classification" });
    }

    if (name === undefined && classification === undefined) {
      return reply.code(400).send({ error: "project_update_required" });
    }

    const allowed = await requirePermission(store, request, reply, "projects:update", {
      tenantId: project.tenantId,
      projectId: project.id,
      classification: classification ?? project.classification,
      entityType: "project",
      entityId: project.id
    });

    if (!allowed) {
      return;
    }

    const updatedProject = await projectRepository.update(
      toProjectReadScope(request.tenantContext),
      project.id,
      {
        ...(name ? { name } : {}),
        ...(classification ? { classification } : {})
      }
    );

    if (!updatedProject) {
      return reply.code(404).send({ error: "project_not_found" });
    }

    appendAuditEvent(store, request, {
      action: "project.updated",
      entityType: "project",
      entityId: updatedProject.id,
      result: "success",
      metadata: {
        classification: updatedProject.classification
      }
    });

    return { project: toProjectResponse(updatedProject) };
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

  app.get<{
    Querystring: {
      actorType?: AuditActorType;
      action?: string;
      result?: AuditResult;
      limit?: number;
    };
  }>("/audit-events", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const allowed = await requirePermission(store, request, reply, "audit:read", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "audit_event"
    });

    if (!allowed) {
      return;
    }

    const limit = clampInteger(request.query.limit ?? 50, 1, 100);
    const action = normalizeName(request.query.action);

    if (request.query.actorType && !isAuditActorType(request.query.actorType)) {
      return reply.code(400).send({ error: "invalid_audit_actor_type" });
    }

    if (request.query.result && !isAuditResult(request.query.result)) {
      return reply.code(400).send({ error: "invalid_audit_result" });
    }

    const filters = {
      tenantId: request.tenantContext.tenant.id,
      limit,
      ...(request.query.actorType ? { actorType: request.query.actorType } : {}),
      ...(action ? { action } : {}),
      ...(request.query.result ? { result: request.query.result } : {})
    };

    return {
      auditEvents: filterAuditEvents(store, filters).map(toAuditEventResponse)
    };
  });

  app.get("/security-dashboard", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const allowed = await requirePermission(store, request, reply, "security:read", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "security_dashboard"
    });

    if (!allowed) {
      return;
    }

    return buildSecurityDashboardResponse(store, request.tenantContext.tenant.id);
  });

  app.get("/share-links", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const allowed = await requirePermission(store, request, reply, "documents:read", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "share_link"
    });

    if (!allowed) {
      return;
    }

    return {
      shareLinks: (await shareLinkRepository.list(request.tenantContext.tenant.id)).map(
        toShareLinkResponse
      )
    };
  });

  app.get("/api-keys", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const allowed = await requirePermission(store, request, reply, "api_keys:read", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "api_key"
    });

    if (!allowed) {
      return;
    }

    return {
      apiKeys: (await apiKeyRepository.list(request.tenantContext.tenant.id)).map(
        toApiKeyResponse
      )
    };
  });

  app.post<{
    Body: {
      name?: string;
      scopes?: ApiKeyScope[];
      expiresInDays?: number;
    };
  }>("/api-keys", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const allowed = await requirePermission(store, request, reply, "api_keys:create", {
      tenantId: request.tenantContext.tenant.id,
      entityType: "api_key"
    });

    if (!allowed) {
      return;
    }

    const name = normalizeName(request.body.name);
    const scopes = request.body.scopes;

    if (!name) {
      return reply.code(400).send({ error: "api_key_name_required" });
    }

    if (!scopes?.length || !scopes.every(isApiKeyScope)) {
      return reply.code(400).send({ error: "invalid_api_key_scopes" });
    }

    const expiresInDays =
      request.body.expiresInDays === undefined
        ? undefined
        : clampInteger(request.body.expiresInDays, 1, 365);
    const apiKeyValue = createApiKeyValue(request.tenantContext.tenant.id);
    const apiKey = await apiKeyRepository.create({
      tenantId: request.tenantContext.tenant.id,
      name,
      keyPrefix: apiKeyValue.split(".")[0] ?? "tv_live",
      keyHash: hashSecret(apiKeyValue),
      scopes: Array.from(new Set(scopes)),
      ...(expiresInDays
        ? { expiresAt: new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000) }
        : {}),
      createdBy: request.tenantContext.user.id
    });

    appendAuditEvent(store, request, {
      action: "api_key.created",
      entityType: "api_key",
      entityId: apiKey.id,
      result: "success",
      metadata: {
        keyPrefix: apiKey.keyPrefix,
        scopes: apiKey.scopes,
        expiresAt: apiKey.expiresAt?.toISOString()
      }
    });

    return reply.code(201).send({
      apiKey: toApiKeyResponse(apiKey),
      key: apiKeyValue
    });
  });

  app.delete<{ Params: { apiKeyId: string } }>(
    "/api-keys/:apiKeyId",
    async (request, reply) => {
      await requireTenantContext(store, request, reply);

      if (!request.tenantContext) {
        return;
      }

      const allowed = await requirePermission(store, request, reply, "api_keys:revoke", {
        tenantId: request.tenantContext.tenant.id,
        entityType: "api_key",
        entityId: request.params.apiKeyId
      });

      if (!allowed) {
        return;
      }

      const apiKey = await apiKeyRepository.revoke(
        request.tenantContext.tenant.id,
        request.params.apiKeyId
      );

      if (!apiKey) {
        return reply.code(404).send({ error: "api_key_not_found" });
      }

      appendAuditEvent(store, request, {
        action: "api_key.revoked",
        entityType: "api_key",
        entityId: apiKey.id,
        result: "success",
        metadata: {
          keyPrefix: apiKey.keyPrefix
        }
      });

      return { apiKey: toApiKeyResponse(apiKey) };
    }
  );

  app.post<{
    Body: {
      documentId?: string;
      expiresInMinutes?: number;
      maxDownloads?: number;
    };
  }>("/share-links", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    const documentId = request.body.documentId;

    if (!documentId) {
      return reply.code(400).send({ error: "document_required" });
    }

    const document =
      (await documentRepository.findByIdForAuthorization?.(documentId)) ??
      (await documentRepository.findVisibleById(toDocumentReadScope(request.tenantContext), documentId));

    if (!document) {
      return reply.code(404).send({ error: "document_not_found" });
    }

    const allowed = await requirePermission(store, request, reply, "documents:update", {
      tenantId: document.tenantId,
      projectId: document.projectId,
      classification: document.classification,
      entityType: "document",
      entityId: document.id
    });

    if (!allowed) {
      return;
    }

    const version = await documentRepository.findCurrentVersionForDownload(
      toDocumentReadScope(request.tenantContext),
      document.id
    );

    if (!version || version.scanStatus !== "clean") {
      return reply.code(409).send({ error: "document_not_available_for_sharing" });
    }

    const expiresInMinutes = clampInteger(request.body.expiresInMinutes ?? 60, 1, 10080);
    const maxDownloads =
      request.body.maxDownloads === undefined
        ? undefined
        : clampInteger(request.body.maxDownloads, 1, 100);
    const token = createShareToken(request.tenantContext.tenant.id);
    const shareLink = await shareLinkRepository.create({
      tenantId: request.tenantContext.tenant.id,
      documentId: document.id,
      tokenHash: hashSecret(token),
      expiresAt: new Date(Date.now() + expiresInMinutes * 60 * 1000),
      ...(maxDownloads ? { maxDownloads } : {}),
      createdBy: request.tenantContext.user.id
    });

    appendAuditEvent(store, request, {
      action: "share_link.created",
      entityType: "share_link",
      entityId: shareLink.id,
      result: "success",
      metadata: {
        documentId: document.id,
        expiresAt: shareLink.expiresAt.toISOString(),
        maxDownloads: shareLink.maxDownloads
      }
    });

    return reply.code(201).send({
      shareLink: toShareLinkResponse(shareLink),
      shareToken: token
    });
  });

  app.delete<{ Params: { shareLinkId: string } }>(
    "/share-links/:shareLinkId",
    async (request, reply) => {
      await requireTenantContext(store, request, reply);

      if (!request.tenantContext) {
        return;
      }

      const shareLink = await shareLinkRepository.findById(
        request.tenantContext.tenant.id,
        request.params.shareLinkId
      );

      if (!shareLink) {
        return reply.code(404).send({ error: "share_link_not_found" });
      }

      const document =
        (await documentRepository.findByIdForAuthorization?.(shareLink.documentId)) ??
        (await documentRepository.findVisibleById(
          toDocumentReadScope(request.tenantContext),
          shareLink.documentId
        ));

      if (!document) {
        return reply.code(404).send({ error: "document_not_found" });
      }

      const allowed = await requirePermission(store, request, reply, "documents:update", {
        tenantId: document.tenantId,
        projectId: document.projectId,
        classification: document.classification,
        entityType: "share_link",
        entityId: shareLink.id
      });

      if (!allowed) {
        return;
      }

      const revokedShareLink = await shareLinkRepository.revoke(
        request.tenantContext.tenant.id,
        shareLink.id
      );

      appendAuditEvent(store, request, {
        action: "share_link.revoked",
        entityType: "share_link",
        entityId: shareLink.id,
        result: "success",
        metadata: {
          documentId: shareLink.documentId
        }
      });

      return { shareLink: toShareLinkResponse(revokedShareLink ?? shareLink) };
    }
  );

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

  app.get<{ Params: { token: string } }>("/public/share-links/:token", async (request, reply) => {
    const tenantId = parseShareTokenTenantId(request.params.token);
    const shareLink = await shareLinkRepository.findByTokenHash(
      hashSecret(request.params.token),
      tenantId
    );

    if (!shareLink) {
      return reply.code(404).send({ error: "share_link_not_found" });
    }

    if (shareLink.revokedAt) {
      appendPublicShareLinkAuditEvent(store, request, shareLink, "share_link.denied", "failure", {
        reason: "revoked"
      });
      return reply.code(403).send({ error: "share_link_revoked" });
    }

    if (shareLink.expiresAt <= new Date()) {
      appendPublicShareLinkAuditEvent(store, request, shareLink, "share_link.denied", "failure", {
        reason: "expired"
      });
      return reply.code(410).send({ error: "share_link_expired" });
    }

    if (
      shareLink.maxDownloads !== undefined &&
      shareLink.downloadCount >= shareLink.maxDownloads
    ) {
      appendPublicShareLinkAuditEvent(store, request, shareLink, "share_link.denied", "failure", {
        reason: "max_downloads_reached"
      });
      return reply.code(403).send({ error: "share_link_download_limit_reached" });
    }

    const document = await documentRepository.findVisibleById(
      {
        tenantId: shareLink.tenantId,
        role: "owner"
      },
      shareLink.documentId
    );

    if (!document) {
      appendPublicShareLinkAuditEvent(store, request, shareLink, "share_link.denied", "failure", {
        reason: "document_not_found"
      });
      return reply.code(404).send({ error: "document_not_found" });
    }

    const version = await documentRepository.findCurrentVersionForDownload(
      {
        tenantId: shareLink.tenantId,
        role: "owner"
      },
      document.id
    );

    if (!version || version.scanStatus !== "clean") {
      appendPublicShareLinkAuditEvent(store, request, shareLink, "share_link.denied", "failure", {
        reason: "document_not_available"
      });
      return reply.code(409).send({ error: "document_not_available" });
    }

    const signedDownload = await storage.createSignedDownload({
      storageKey: version.storageKey,
      expiresInSeconds: 300
    });
    const usedShareLink = await shareLinkRepository.incrementDownload(
      shareLink.tenantId,
      shareLink.id
    );
    appendPublicShareLinkAuditEvent(store, request, usedShareLink ?? shareLink, "share_link.used", "success", {
      documentId: document.id,
      versionId: version.id
    });

    return {
      download: {
        documentId: document.id,
        versionId: version.id,
        originalFilename: version.originalFilename,
        mimeType: version.mimeType,
        sizeBytes: version.sizeBytes,
        expiresInSeconds: 300,
        expiresAt: signedDownload.expiresAt.toISOString()
      },
      shareLink: toShareLinkResponse(usedShareLink ?? shareLink)
    };
  });

  app.get("/api/v1/documents", async (request, reply) => {
    const apiAuth = await requireApiKey(store, apiKeyRepository, request, reply, "documents:read");

    if (!apiAuth) {
      return;
    }

    const documents = await documentRepository.list({
      tenantId: apiAuth.apiKey.tenantId,
      role: "owner"
    });
    appendApiKeyAuditEvent(store, request, apiAuth.apiKey, "api.documents.list", "success", {
      count: documents.length
    });

    return { documents: documents.map(toDocumentResponse) };
  });

  app.post<{
    Body: {
      title?: string;
      projectId?: string;
      classification?: DocumentClassification;
    };
  }>("/api/v1/documents", async (request, reply) => {
    const apiAuth = await requireApiKey(store, apiKeyRepository, request, reply, "documents:write");

    if (!apiAuth) {
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

    const project = await projectRepository.findVisibleById(
      {
        tenantId: apiAuth.apiKey.tenantId,
        role: "owner"
      },
      projectId
    );

    if (!project) {
      return reply.code(404).send({ error: "project_not_found" });
    }

    const document = await documentRepository.create({
      tenantId: apiAuth.apiKey.tenantId,
      projectId,
      title,
      classification,
      createdBy: apiAuth.apiKey.id
    });
    appendApiKeyAuditEvent(store, request, apiAuth.apiKey, "api.documents.created", "success", {
      documentId: document.id,
      projectId: document.projectId
    });

    return reply.code(201).send({ document: toDocumentResponse(document) });
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

    const project =
      (await projectRepository.findByIdForAuthorization?.(projectId)) ??
      (await projectRepository.findVisibleById(toProjectReadScope(request.tenantContext), projectId));

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
    appendAuditEvent(store, request, {
      action: "document.created",
      entityType: "document",
      entityId: document.id,
      result: "success",
      metadata: {
        projectId: document.projectId,
        classification: document.classification
      }
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
      appendAuditEvent(store, request, {
        action: "document.deleted",
        entityType: "document",
        entityId: document.id,
        result: "success",
        metadata: {
          projectId: document.projectId,
          classification: document.classification
        }
      });

      return reply.code(204).send();
    }
  );

  app.post<{
    Params: { documentId: string };
    Body: {
      originalFilename?: string;
      mimeType?: string;
      sizeBytes?: number;
      contentBase64?: string;
    };
  }>("/documents/:documentId/versions", async (request, reply) => {
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

    const allowed = await requirePermission(store, request, reply, "documents:update", {
      tenantId: document.tenantId,
      projectId: document.projectId,
      classification: document.classification,
      entityType: "document",
      entityId: document.id
    });

    if (!allowed) {
      return;
    }

    const originalFilename = normalizeName(request.body.originalFilename);
    const mimeType = request.body.mimeType;
    const sizeBytes = request.body.sizeBytes;
    const contentBase64 = request.body.contentBase64;

    if (!originalFilename || !mimeType || typeof sizeBytes !== "number" || !contentBase64) {
      return reply.code(400).send({ error: "upload_payload_required" });
    }

    const content = decodeBase64(contentBase64);

    if (!content) {
      return reply.code(400).send({ error: "invalid_file_content" });
    }

    const validation = validateDocumentUpload({
      filename: originalFilename,
      mimeType,
      sizeBytes,
      content
    });

    if (!validation.valid) {
      return reply.code(400).send({ error: validation.reason });
    }

    const version = await documentRepository.uploadVersion({
      tenantId: request.tenantContext.tenant.id,
      documentId: document.id,
      storageKey: (
        await storage.put({
          tenantId: request.tenantContext.tenant.id,
          documentId: document.id,
          contentType: mimeType,
          content
        })
      ).storageKey,
      originalFilename,
      mimeType,
      sizeBytes: content.byteLength,
      sha256: createHash("sha256").update(content).digest("hex"),
      uploadedBy: request.tenantContext.user.id
    });
    await scanQueue.enqueue({
      tenantId: request.tenantContext.tenant.id,
      documentId: document.id,
      versionId: version.id,
      storageKey: version.storageKey,
      queuedBy: request.tenantContext.user.id
    });
    appendAuditEvent(store, request, {
      action: "document.uploaded",
      entityType: "document_version",
      entityId: version.id,
      result: "success",
      metadata: {
        documentId: document.id,
        originalFilename,
        mimeType,
        sizeBytes: content.byteLength,
        sha256: version.sha256
      }
    });

    return reply.code(201).send({ version: toDocumentVersionResponse(version) });
  });

  app.post<{
    Params: { versionId: string };
    Body: { scanStatus?: "clean" | "blocked" };
  }>("/document-versions/:versionId/scan-result", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    if (request.tenantContext.membership.role !== "owner" && request.tenantContext.membership.role !== "admin") {
      return reply.code(403).send({ error: "permission_denied" });
    }

    const scanStatus = request.body.scanStatus;

    if (scanStatus !== "clean" && scanStatus !== "blocked") {
      return reply.code(400).send({ error: "invalid_scan_status" });
    }

    const version = await documentRepository.updateScanStatus(
      toDocumentReadScope(request.tenantContext),
      request.params.versionId,
      scanStatus
    );

    if (!version) {
      return reply.code(404).send({ error: "document_version_not_found" });
    }

    appendAuditEvent(store, request, {
      action: scanStatus === "clean" ? "document.scan_clean" : "document.scan_blocked",
      entityType: "document_version",
      entityId: version.id,
      result: scanStatus === "clean" ? "success" : "failure",
      metadata: {
        documentId: version.documentId,
        scanStatus
      }
    });

    return { version: toDocumentVersionResponse(version) };
  });

  app.post("/internal/scan-jobs/process-next", async (request, reply) => {
    await requireTenantContext(store, request, reply);

    if (!request.tenantContext) {
      return;
    }

    if (request.tenantContext.membership.role !== "owner" && request.tenantContext.membership.role !== "admin") {
      return reply.code(403).send({ error: "permission_denied" });
    }

    const job = await scanQueue.processNext(request.tenantContext.tenant.id);

    if (!job) {
      return reply.code(204).send();
    }

    return {
      scanJob: {
        id: job.id,
        tenantId: job.tenantId,
        documentId: job.documentId,
        versionId: job.versionId,
        status: job.status,
        attempts: job.attempts,
        updatedAt: job.updatedAt.toISOString()
      }
    };
  });

  app.get<{ Params: { documentId: string } }>(
    "/documents/:documentId/download",
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

      const version = await documentRepository.findCurrentVersionForDownload(
        toDocumentReadScope(request.tenantContext),
        document.id
      );

      if (!version) {
        return reply.code(404).send({ error: "document_version_not_found" });
      }

      if (version.scanStatus !== "clean") {
        return reply.code(409).send({ error: "file_not_available_until_clean_scan" });
      }

      const signedDownload = await storage.createSignedDownload({
        storageKey: version.storageKey,
        expiresInSeconds: 300
      });
      appendAuditEvent(store, request, {
        action: "document.downloaded",
        entityType: "document_version",
        entityId: version.id,
        result: "success",
        metadata: {
          documentId: document.id,
          expiresAt: signedDownload.expiresAt.toISOString()
        }
      });

      return {
        download: {
          documentId: document.id,
          versionId: version.id,
          originalFilename: version.originalFilename,
          mimeType: version.mimeType,
          sizeBytes: version.sizeBytes,
          expiresInSeconds: 300,
          expiresAt: signedDownload.expiresAt.toISOString()
        }
      };
    }
  );

  return app;
}

function normalizeName(name: string | undefined): string | undefined {
  const normalized = name?.trim().replace(/\s+/g, " ");

  return normalized || undefined;
}

function setSecurityHeaders(reply: FastifyReply, env: string): void {
  reply.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  reply.header("X-Content-Type-Options", "nosniff");
  reply.header("X-Frame-Options", "DENY");
  reply.header("Referrer-Policy", "strict-origin-when-cross-origin");
  reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  reply.header("Cross-Origin-Resource-Policy", "same-site");

  if (env === "production") {
    reply.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}

function requiresCsrfCheck(request: FastifyRequest): boolean {
  const method = request.method.toUpperCase();

  if (method !== "POST" && method !== "PATCH" && method !== "PUT" && method !== "DELETE") {
    return false;
  }

  if (!request.headers.origin || !isAllowedOrigin(request.headers.origin)) {
    return false;
  }

  if (request.url === "/auth/dev-login" || request.url === "/invitations/accept") {
    return false;
  }

  if (!readCookie(request, sessionCookieName)) {
    return false;
  }

  return !request.headers.authorization?.startsWith("Bearer ");
}

type RequestShapeRule = {
  method: string;
  pattern: RegExp;
  bodyKeys?: readonly string[];
  queryKeys?: readonly string[];
};

const requestShapeRules: RequestShapeRule[] = [
  { method: "POST", pattern: /^\/auth\/dev-login$/, bodyKeys: ["email"] },
  { method: "POST", pattern: /^\/tenants$/, bodyKeys: ["name", "slug"] },
  { method: "POST", pattern: /^\/projects$/, bodyKeys: ["name", "classification"] },
  { method: "PATCH", pattern: /^\/projects\/[^/]+$/, bodyKeys: ["name", "classification"] },
  { method: "PATCH", pattern: /^\/memberships\/[^/]+\/role$/, bodyKeys: ["role"] },
  {
    method: "GET",
    pattern: /^\/audit-events$/,
    queryKeys: ["actorType", "action", "result", "limit"]
  },
  { method: "POST", pattern: /^\/api-keys$/, bodyKeys: ["name", "scopes", "expiresInDays"] },
  { method: "POST", pattern: /^\/share-links$/, bodyKeys: ["documentId", "expiresInMinutes", "maxDownloads"] },
  { method: "POST", pattern: /^\/tenant\/invitations$/, bodyKeys: ["email", "role"] },
  { method: "POST", pattern: /^\/invitations\/accept$/, bodyKeys: ["token", "name"] },
  { method: "POST", pattern: /^\/api\/v1\/documents$/, bodyKeys: ["title", "projectId", "classification"] },
  { method: "POST", pattern: /^\/documents$/, bodyKeys: ["title", "projectId", "classification"] },
  {
    method: "POST",
    pattern: /^\/documents\/[^/]+\/versions$/,
    bodyKeys: ["originalFilename", "mimeType", "sizeBytes", "contentBase64"]
  },
  { method: "POST", pattern: /^\/document-versions\/[^/]+\/scan-result$/, bodyKeys: ["scanStatus"] },
  { method: "POST", pattern: /^\/internal\/scan-jobs\/process-next$/, bodyKeys: [] }
];

function validateRequestShape(
  request: FastifyRequest
): { valid: true } | { valid: false; reason: string } {
  const path = request.url.split("?")[0] ?? request.url;
  const rule = requestShapeRules.find(
    (candidate) => candidate.method === request.method && candidate.pattern.test(path)
  );

  if (!rule) {
    return { valid: true };
  }

  if (rule.bodyKeys && !hasOnlyAllowedKeys(request.body, rule.bodyKeys)) {
    return { valid: false, reason: "invalid_request_body" };
  }

  if (rule.queryKeys && !hasOnlyAllowedKeys(request.query, rule.queryKeys)) {
    return { valid: false, reason: "invalid_query_parameters" };
  }

  return { valid: true };
}

function hasOnlyAllowedKeys(value: unknown, allowedKeys: readonly string[]): boolean {
  if (value === undefined) {
    return true;
  }

  if (!isPlainObject(value)) {
    return false;
  }

  return Object.keys(value).every((key) => allowedKeys.includes(key));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const rateLimitRules: RateLimitRule[] = [
  {
    name: "auth",
    limit: 5,
    windowMs: 60_000,
    match: (request) => request.method === "POST" && request.url === "/auth/dev-login",
    key: (request) => `auth:${request.ip}`
  },
  {
    name: "api-keys",
    limit: 20,
    windowMs: 60_000,
    match: (request) => request.url.startsWith("/api-keys"),
    key: (request) => `api-keys:${request.ip}:${request.headers["x-tenant-id"] ?? "none"}`
  },
  {
    name: "external-api",
    limit: 60,
    windowMs: 60_000,
    match: (request) => request.url.startsWith("/api/v1/"),
    key: (request) =>
      `external-api:${request.headers.authorization ?? "anonymous"}:${request.ip}`
  },
  {
    name: "share-links",
    limit: 30,
    windowMs: 60_000,
    match: (request) =>
      request.url.startsWith("/share-links") || request.url.startsWith("/public/share-links"),
    key: (request) => `share-links:${request.ip}`
  },
  {
    name: "uploads",
    limit: 20,
    windowMs: 60_000,
    match: (request) => request.method === "POST" && /\/documents\/[^/]+\/versions/.test(request.url),
    key: (request) => `uploads:${request.ip}:${request.headers["x-tenant-id"] ?? "none"}`
  }
];

async function applyRateLimit(
  rateLimiter: RateLimiter,
  request: FastifyRequest
): Promise<{ allowed: true } | { allowed: false; retryAfterMs: number }> {
  const rule = rateLimitRules.find((candidate) => candidate.match(request));

  if (!rule) {
    return { allowed: true };
  }

  const key = `${rule.name}:${rule.key(request)}`;

  return rateLimiter.consume(rule, key);
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

function appendAuditEvent(
  store: AppStore,
  request: Parameters<typeof requirePermission>[1],
  input: {
    action: string;
    entityType: string;
    entityId?: string;
    result: "success" | "failure";
    metadata: Record<string, unknown>;
  }
): void {
  if (!request.tenantContext) {
    return;
  }

  store.auditEvents.push({
    id: `audit_${randomUUID()}`,
    tenantId: request.tenantContext.tenant.id,
    actorUserId: request.tenantContext.user.id,
    actorType: "user",
    action: input.action,
    entityType: input.entityType,
    ...(input.entityId ? { entityId: input.entityId } : {}),
    result: input.result,
    ipHash: hashSecret(request.ip),
    userAgent: request.headers["user-agent"] ?? "unknown",
    metadata: redactAuditMetadata(input.metadata),
    createdAt: new Date()
  });
}

function appendPublicShareLinkAuditEvent(
  store: AppStore,
  request: FastifyRequest,
  shareLink: {
    id: string;
    tenantId: string;
    documentId: string;
  },
  action: string,
  result: "success" | "failure",
  metadata: Record<string, unknown>
): void {
  store.auditEvents.push({
    id: `audit_${randomUUID()}`,
    tenantId: shareLink.tenantId,
    actorType: "system",
    action,
    entityType: "share_link",
    entityId: shareLink.id,
    result,
    ipHash: hashSecret(request.ip),
    userAgent: request.headers["user-agent"] ?? "unknown",
    metadata: redactAuditMetadata({
      documentId: shareLink.documentId,
      ...metadata
    }),
    createdAt: new Date()
  });
}

async function requireApiKey(
  store: AppStore,
  apiKeyRepository: ApiKeyRepository,
  request: FastifyRequest,
  reply: Parameters<typeof requirePermission>[2],
  requiredScope: ApiKeyScope
): Promise<{ apiKey: ApiKey } | undefined> {
  const authorization = request.headers.authorization;
  const key = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : undefined;

  if (!key) {
    await reply.code(401).send({ error: "api_key_required" });
    return undefined;
  }

  const tenantId = parseApiKeyTenantId(key);
  const apiKey = await apiKeyRepository.findByHash(hashSecret(key), tenantId);

  if (!apiKey) {
    await reply.code(401).send({ error: "api_key_invalid" });
    return undefined;
  }

  if (apiKey.revokedAt) {
    appendApiKeyAuditEvent(store, request, apiKey, "api_key.denied", "failure", {
      reason: "revoked",
      requiredScope
    });
    await reply.code(401).send({ error: "api_key_revoked" });
    return undefined;
  }

  if (apiKey.expiresAt && apiKey.expiresAt <= new Date()) {
    appendApiKeyAuditEvent(store, request, apiKey, "api_key.denied", "failure", {
      reason: "expired",
      requiredScope
    });
    await reply.code(401).send({ error: "api_key_expired" });
    return undefined;
  }

  if (!apiKey.scopes.includes(requiredScope)) {
    appendApiKeyAuditEvent(store, request, apiKey, "api_key.denied", "failure", {
      reason: "scope_missing",
      requiredScope
    });
    await reply.code(403).send({ error: "api_key_scope_denied" });
    return undefined;
  }

  await apiKeyRepository.markUsed(apiKey.tenantId, apiKey.id);

  return { apiKey };
}

function appendApiKeyAuditEvent(
  store: AppStore,
  request: FastifyRequest,
  apiKey: ApiKey,
  action: string,
  result: "success" | "failure",
  metadata: Record<string, unknown>
): void {
  store.auditEvents.push({
    id: `audit_${randomUUID()}`,
    tenantId: apiKey.tenantId,
    actorType: "api_key",
    action,
    entityType: "api_key",
    entityId: apiKey.id,
    result,
    ipHash: hashSecret(request.ip),
    userAgent: request.headers["user-agent"] ?? "unknown",
    metadata: redactAuditMetadata({
      keyPrefix: apiKey.keyPrefix,
      ...metadata
    }),
    createdAt: new Date()
  });
}

function isDocumentClassification(value: string): value is DocumentClassification {
  return (
    value === "public" ||
    value === "internal" ||
    value === "confidential" ||
    value === "restricted"
  );
}

function toProjectResponse(project: {
  id: string;
  tenantId: string;
  name: string;
  classification: DocumentClassification;
  createdBy: string;
  createdAt: Date;
}) {
  return {
    id: project.id,
    tenantId: project.tenantId,
    name: project.name,
    classification: project.classification,
    createdBy: project.createdBy,
    createdAt: project.createdAt.toISOString()
  };
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

function toDocumentVersionResponse(version: {
  id: string;
  documentId: string;
  originalFilename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  scanStatus: string;
  createdAt: Date;
}) {
  return {
    id: version.id,
    documentId: version.documentId,
    originalFilename: version.originalFilename,
    mimeType: version.mimeType,
    sizeBytes: version.sizeBytes,
    sha256: version.sha256,
    scanStatus: version.scanStatus,
    createdAt: version.createdAt.toISOString()
  };
}

function toAuditEventResponse(event: {
  id: string;
  tenantId: string;
  actorUserId?: string;
  actorType: string;
  action: string;
  entityType: string;
  entityId?: string;
  result: string;
  metadata: Record<string, unknown>;
  createdAt: Date;
}) {
  return {
    id: event.id,
    tenantId: event.tenantId,
    actorType: event.actorType,
    ...(event.actorUserId ? { actorUserId: event.actorUserId } : {}),
    action: event.action,
    entityType: event.entityType,
    ...(event.entityId ? { entityId: event.entityId } : {}),
    result: event.result,
    metadata: event.metadata,
    createdAt: event.createdAt.toISOString()
  };
}

function filterAuditEvents(
  store: AppStore,
  input: {
    tenantId: string;
    actorType?: AuditActorType;
    action?: string;
    result?: AuditResult;
    limit: number;
  }
) {
  return store.auditEvents
    .filter(
      (event) =>
        event.tenantId === input.tenantId &&
        (!input.actorType || event.actorType === input.actorType) &&
        (!input.action || event.action === input.action) &&
        (!input.result || event.result === input.result)
    )
    .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
    .slice(0, input.limit);
}

function buildSecurityDashboardResponse(store: AppStore, tenantId: string) {
  const tenantMemberships = store.memberships.filter(
    (membership) => membership.tenantId === tenantId && membership.status === "active"
  );
  const tenantEvents = store.auditEvents.filter((event) => event.tenantId === tenantId);
  const activeShareLinks = store.shareLinks.filter(
    (shareLink) =>
      shareLink.tenantId === tenantId &&
      !shareLink.revokedAt &&
      shareLink.expiresAt > new Date() &&
      (!shareLink.maxDownloads || shareLink.downloadCount < shareLink.maxDownloads)
  );
  const activeApiKeys = store.apiKeys.filter(
    (apiKey) =>
      apiKey.tenantId === tenantId &&
      !apiKey.revokedAt &&
      (!apiKey.expiresAt || apiKey.expiresAt > new Date())
  );
  const tenantVersions = store.documentVersions.filter((version) => version.tenantId === tenantId);
  const riskyEvents = tenantEvents
    .filter(isRiskySecurityEvent)
    .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
    .slice(0, 10);

  return {
    metrics: {
      mfaRequiredMembers: tenantMemberships.filter((membership) => membership.mfaRequired).length,
      activeMembers: tenantMemberships.length,
      accessDeniedEvents: tenantEvents.filter(
        (event) =>
          event.result === "failure" &&
          (event.action === "authorization.denied" ||
            event.action === "api_key.denied" ||
            event.action === "share_link.denied")
      ).length,
      cleanFiles: tenantVersions.filter((version) => version.scanStatus === "clean").length,
      pendingFiles: tenantVersions.filter((version) => version.scanStatus === "pending_scan").length,
      blockedFiles: tenantVersions.filter((version) => version.scanStatus === "blocked").length,
      activeApiKeys: activeApiKeys.length,
      activeShareLinks: activeShareLinks.length,
      riskyEvents: riskyEvents.length
    },
    alerts: buildSecurityAlerts(tenantEvents, activeApiKeys, activeShareLinks),
    riskyEvents: riskyEvents.map(toAuditEventResponse)
  };
}

function buildSecurityAlerts(
  events: AppStore["auditEvents"],
  activeApiKeys: AppStore["apiKeys"],
  activeShareLinks: AppStore["shareLinks"]
) {
  return [
    {
      id: "access-denied-events",
      severity: events.some(
        (event) =>
          event.result === "failure" &&
          (event.action === "authorization.denied" ||
            event.action === "api_key.denied" ||
            event.action === "share_link.denied")
      )
        ? "medium"
        : "info",
      title: "Access denied activity",
      status: events.some(
        (event) =>
          event.result === "failure" &&
          (event.action === "authorization.denied" ||
            event.action === "api_key.denied" ||
            event.action === "share_link.denied")
      )
        ? "attention"
        : "clear"
    },
    {
      id: "active-api-keys",
      severity: activeApiKeys.length > 0 ? "low" : "info",
      title: "Active API keys",
      status: activeApiKeys.length > 0 ? "monitor" : "clear"
    },
    {
      id: "public-share-links",
      severity: activeShareLinks.length > 0 ? "low" : "info",
      title: "Active share links",
      status: activeShareLinks.length > 0 ? "monitor" : "clear"
    }
  ];
}

function isRiskySecurityEvent(event: AppStore["auditEvents"][number]): boolean {
  return (
    event.action === "authorization.denied" ||
    event.action === "api_key.created" ||
    event.action === "api_key.revoked" ||
    event.action === "api_key.denied" ||
    event.action === "share_link.created" ||
    event.action === "share_link.denied" ||
    event.action === "document.scan_blocked"
  );
}

function toShareLinkResponse(shareLink: {
  id: string;
  tenantId: string;
  documentId: string;
  permission: "download";
  expiresAt: Date;
  maxDownloads?: number;
  downloadCount: number;
  revokedAt?: Date;
  createdBy: string;
  createdAt: Date;
}) {
  return {
    id: shareLink.id,
    tenantId: shareLink.tenantId,
    documentId: shareLink.documentId,
    permission: shareLink.permission,
    expiresAt: shareLink.expiresAt.toISOString(),
    ...(shareLink.maxDownloads === undefined ? {} : { maxDownloads: shareLink.maxDownloads }),
    downloadCount: shareLink.downloadCount,
    ...(shareLink.revokedAt ? { revokedAt: shareLink.revokedAt.toISOString() } : {}),
    createdBy: shareLink.createdBy,
    createdAt: shareLink.createdAt.toISOString()
  };
}

function toApiKeyResponse(apiKey: {
  id: string;
  tenantId: string;
  name: string;
  keyPrefix: string;
  scopes: ApiKeyScope[];
  expiresAt?: Date;
  lastUsedAt?: Date;
  revokedAt?: Date;
  createdBy: string;
  createdAt: Date;
}) {
  return {
    id: apiKey.id,
    tenantId: apiKey.tenantId,
    name: apiKey.name,
    keyPrefix: apiKey.keyPrefix,
    scopes: apiKey.scopes,
    ...(apiKey.expiresAt ? { expiresAt: apiKey.expiresAt.toISOString() } : {}),
    ...(apiKey.lastUsedAt ? { lastUsedAt: apiKey.lastUsedAt.toISOString() } : {}),
    ...(apiKey.revokedAt ? { revokedAt: apiKey.revokedAt.toISOString() } : {}),
    createdBy: apiKey.createdBy,
    createdAt: apiKey.createdAt.toISOString()
  };
}

function decodeBase64(value: string): Buffer | undefined {
  try {
    const buffer = Buffer.from(value, "base64");

    return buffer.byteLength > 0 ? buffer : undefined;
  } catch {
    return undefined;
  }
}

function toDocumentReadScope(context: TenantRequestContext): DocumentReadScope {
  return {
    tenantId: context.tenant.id,
    role: context.membership.role,
    ...(context.membership.projectIds ? { projectIds: context.membership.projectIds } : {})
  };
}

function toProjectReadScope(context: TenantRequestContext): ProjectReadScope {
  return {
    tenantId: context.tenant.id,
    role: context.membership.role,
    ...(context.membership.projectIds ? { projectIds: context.membership.projectIds } : {})
  };
}

function hashSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

function createShareToken(tenantId: string): string {
  return `tv_share_${Buffer.from(tenantId, "utf8").toString("base64url")}.${randomBytes(32).toString("base64url")}`;
}

function parseShareTokenTenantId(token: string): string | undefined {
  if (!token.startsWith("tv_share_")) {
    return undefined;
  }

  const [tenantHint] = token.slice("tv_share_".length).split(".");

  if (!tenantHint) {
    return undefined;
  }

  try {
    return Buffer.from(tenantHint, "base64url").toString("utf8") || undefined;
  } catch {
    return undefined;
  }
}

function createApiKeyValue(tenantId: string): string {
  return `tv_live_${Buffer.from(tenantId, "utf8").toString("base64url")}.${randomBytes(32).toString("base64url")}`;
}

function parseApiKeyTenantId(apiKey: string): string | undefined {
  if (!apiKey.startsWith("tv_live_")) {
    return undefined;
  }

  const [tenantHint] = apiKey.slice("tv_live_".length).split(".");

  if (!tenantHint) {
    return undefined;
  }

  try {
    return Buffer.from(tenantHint, "base64url").toString("utf8") || undefined;
  } catch {
    return undefined;
  }
}

function isApiKeyScope(scope: string): scope is ApiKeyScope {
  return scope === "documents:read" || scope === "documents:write" || scope === "audit:read";
}

function isAuditActorType(value: string): value is AuditActorType {
  return value === "user" || value === "api_key" || value === "system" || value === "support";
}

function isAuditResult(value: string): value is AuditResult {
  return value === "success" || value === "failure";
}

function clampInteger(value: number | string, min: number, max: number): number {
  const numericValue = typeof value === "string" ? Number(value) : value;

  if (!Number.isFinite(numericValue)) {
    return min;
  }

  return Math.min(Math.max(Math.trunc(numericValue), min), max);
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
