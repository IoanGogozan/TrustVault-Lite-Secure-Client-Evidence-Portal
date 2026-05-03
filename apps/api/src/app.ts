import Fastify, { type FastifyInstance } from "fastify";
import { readBaseConfig } from "@trustvault/config";
import {
  createSession,
  requireAuth,
  requireTenantContext,
  revokeSession
} from "./auth.js";
import { createDemoStore, type AppStore } from "./domain.js";
import { clearSessionCookie, setSessionCookie } from "./http.js";

export type BuildAppOptions = {
  store?: AppStore;
};

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const config = readBaseConfig();
  const store = options.store ?? createDemoStore();
  const app = Fastify({
    logger: config.env === "production"
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

  return app;
}

