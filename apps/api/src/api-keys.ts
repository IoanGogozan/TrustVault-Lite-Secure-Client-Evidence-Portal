import { withTenantContext, type DatabasePool } from "@trustvault/database";
import type { ApiKey, ApiKeyScope, AppStore } from "./domain.js";

export type CreateApiKeyInput = {
  id: string;
  tenantId: string;
  name: string;
  keyPrefix: string;
  keyHash: string;
  scopes: ApiKeyScope[];
  expiresAt?: Date;
  createdBy: string;
};

export type ApiKeyRepository = {
  list(tenantId: string): Promise<ApiKey[]>;
  create(input: CreateApiKeyInput): Promise<ApiKey>;
  revoke(tenantId: string, apiKeyId: string): Promise<ApiKey | undefined>;
  findByIdAndHash(apiKeyId: string, keyHash: string, tenantId?: string): Promise<ApiKey | undefined>;
  markUsed(tenantId: string, apiKeyId: string): Promise<ApiKey | undefined>;
};

export class InMemoryApiKeyRepository implements ApiKeyRepository {
  constructor(private readonly store: AppStore) {}

  async list(tenantId: string): Promise<ApiKey[]> {
    return this.store.apiKeys
      .filter((apiKey) => apiKey.tenantId === tenantId)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());
  }

  async create(input: CreateApiKeyInput): Promise<ApiKey> {
    const apiKey = {
      id: input.id,
      tenantId: input.tenantId,
      name: input.name,
      keyPrefix: input.keyPrefix,
      keyHash: input.keyHash,
      scopes: input.scopes,
      ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
      createdBy: input.createdBy,
      createdAt: new Date()
    };

    this.store.apiKeys.push(apiKey);

    return apiKey;
  }

  async revoke(tenantId: string, apiKeyId: string): Promise<ApiKey | undefined> {
    const apiKey = this.store.apiKeys.find(
      (candidate) => candidate.id === apiKeyId && candidate.tenantId === tenantId
    );

    if (!apiKey) {
      return undefined;
    }

    apiKey.revokedAt = new Date();

    return apiKey;
  }

  async findByIdAndHash(
    apiKeyId: string,
    keyHash: string,
    tenantId?: string
  ): Promise<ApiKey | undefined> {
    return this.store.apiKeys.find(
      (apiKey) =>
        apiKey.id === apiKeyId &&
        apiKey.keyHash === keyHash &&
        (!tenantId || apiKey.tenantId === tenantId)
    );
  }

  async markUsed(tenantId: string, apiKeyId: string): Promise<ApiKey | undefined> {
    const apiKey = this.store.apiKeys.find(
      (candidate) => candidate.id === apiKeyId && candidate.tenantId === tenantId
    );

    if (!apiKey) {
      return undefined;
    }

    apiKey.lastUsedAt = new Date();

    return apiKey;
  }
}

export class PostgresApiKeyRepository implements ApiKeyRepository {
  constructor(private readonly database: DatabasePool) {}

  async list(tenantId: string): Promise<ApiKey[]> {
    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ApiKeyRow>(
        `SELECT id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_by, created_at
         FROM api_keys
         ORDER BY created_at DESC`
      );

      return result.rows.map(fromApiKeyRow);
    });
  }

  async create(input: CreateApiKeyInput): Promise<ApiKey> {
    return withTenantContext(this.database, input.tenantId, async (tx) => {
      const result = await tx.execute<ApiKeyRow>(
        `INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_by, created_at`,
        [
          input.id,
          input.tenantId,
          input.name,
          input.keyPrefix,
          input.keyHash,
          input.scopes,
          input.expiresAt ?? null,
          input.createdBy
        ]
      );
      const row = result.rows[0];

      if (!row) {
        throw new Error("API key insert did not return a row");
      }

      return fromApiKeyRow(row);
    });
  }

  async revoke(tenantId: string, apiKeyId: string): Promise<ApiKey | undefined> {
    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ApiKeyRow>(
        `UPDATE api_keys
         SET revoked_at = now()
         WHERE id = $1
         RETURNING id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_by, created_at`,
        [apiKeyId]
      );

      return result.rows[0] ? fromApiKeyRow(result.rows[0]) : undefined;
    });
  }

  async findByIdAndHash(
    apiKeyId: string,
    keyHash: string,
    tenantId?: string
  ): Promise<ApiKey | undefined> {
    if (!tenantId) {
      return this.database.transaction(async (tx) => {
        const result = await tx.execute<ApiKeyRow>(
          `SELECT id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_by, created_at
           FROM resolve_api_key_by_secret($1, $2)`,
          [apiKeyId, keyHash]
        );

        return result.rows[0] ? fromApiKeyRow(result.rows[0]) : undefined;
      });
    }

    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ApiKeyRow>(
        `SELECT id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_by, created_at
         FROM api_keys
         WHERE id = $1
           AND key_hash = $2`,
        [apiKeyId, keyHash]
      );

      return result.rows[0] ? fromApiKeyRow(result.rows[0]) : undefined;
    });
  }

  async markUsed(tenantId: string, apiKeyId: string): Promise<ApiKey | undefined> {
    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ApiKeyRow>(
        `UPDATE api_keys
         SET last_used_at = now()
         WHERE id = $1
         RETURNING id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_by, created_at`,
        [apiKeyId]
      );

      return result.rows[0] ? fromApiKeyRow(result.rows[0]) : undefined;
    });
  }
}

type ApiKeyRow = {
  id: string;
  tenant_id: string;
  name: string;
  key_prefix: string;
  key_hash: string;
  scopes: ApiKeyScope[];
  expires_at: Date | string | null;
  last_used_at: Date | string | null;
  revoked_at: Date | string | null;
  created_by: string;
  created_at: Date | string;
};

function fromApiKeyRow(row: ApiKeyRow): ApiKey {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    keyPrefix: row.key_prefix,
    keyHash: row.key_hash,
    scopes: row.scopes,
    ...(row.expires_at ? { expiresAt: new Date(row.expires_at) } : {}),
    ...(row.last_used_at ? { lastUsedAt: new Date(row.last_used_at) } : {}),
    ...(row.revoked_at ? { revokedAt: new Date(row.revoked_at) } : {}),
    createdBy: row.created_by,
    createdAt: new Date(row.created_at)
  };
}
