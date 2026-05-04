import { withTenantContext, type DatabasePool } from "@trustvault/database";
import type { AppStore, ShareLink } from "./domain.js";

export type CreateShareLinkInput = {
  id: string;
  tenantId: string;
  documentId: string;
  tokenHash: string;
  expiresAt: Date;
  maxDownloads?: number;
  createdBy: string;
};

export type ShareLinkRepository = {
  list(tenantId: string): Promise<ShareLink[]>;
  findById(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined>;
  create(input: CreateShareLinkInput): Promise<ShareLink>;
  revoke(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined>;
  findByIdAndTokenHash(
    shareLinkId: string,
    tokenHash: string,
    tenantId?: string
  ): Promise<ShareLink | undefined>;
  incrementDownload(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined>;
};

export class InMemoryShareLinkRepository implements ShareLinkRepository {
  constructor(private readonly store: AppStore) {}

  async list(tenantId: string): Promise<ShareLink[]> {
    return this.store.shareLinks
      .filter((shareLink) => shareLink.tenantId === tenantId)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());
  }

  async findById(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined> {
    return this.store.shareLinks.find(
      (shareLink) => shareLink.id === shareLinkId && shareLink.tenantId === tenantId
    );
  }

  async create(input: CreateShareLinkInput): Promise<ShareLink> {
    const shareLink = {
      id: input.id,
      tenantId: input.tenantId,
      documentId: input.documentId,
      tokenHash: input.tokenHash,
      permission: "download" as const,
      expiresAt: input.expiresAt,
      ...(input.maxDownloads ? { maxDownloads: input.maxDownloads } : {}),
      downloadCount: 0,
      createdBy: input.createdBy,
      createdAt: new Date()
    };

    this.store.shareLinks.push(shareLink);

    return shareLink;
  }

  async revoke(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined> {
    const shareLink = await this.findById(tenantId, shareLinkId);

    if (!shareLink) {
      return undefined;
    }

    shareLink.revokedAt = new Date();

    return shareLink;
  }

  async findByIdAndTokenHash(
    shareLinkId: string,
    tokenHash: string,
    tenantId?: string
  ): Promise<ShareLink | undefined> {
    return this.store.shareLinks.find(
      (shareLink) =>
        shareLink.id === shareLinkId &&
        shareLink.tokenHash === tokenHash &&
        (!tenantId || shareLink.tenantId === tenantId)
    );
  }

  async incrementDownload(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined> {
    const shareLink = await this.findById(tenantId, shareLinkId);

    if (!shareLink) {
      return undefined;
    }

    shareLink.downloadCount += 1;

    return shareLink;
  }
}

export class PostgresShareLinkRepository implements ShareLinkRepository {
  constructor(private readonly database: DatabasePool) {}

  async list(tenantId: string): Promise<ShareLink[]> {
    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ShareLinkRow>(
        `SELECT id, tenant_id, document_id, token_hash, permission, expires_at, max_downloads, download_count, revoked_at, created_by, created_at
         FROM share_links
         ORDER BY created_at DESC`
      );

      return result.rows.map(fromShareLinkRow);
    });
  }

  async findById(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined> {
    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ShareLinkRow>(
        `SELECT id, tenant_id, document_id, token_hash, permission, expires_at, max_downloads, download_count, revoked_at, created_by, created_at
         FROM share_links
         WHERE id = $1`,
        [shareLinkId]
      );

      return result.rows[0] ? fromShareLinkRow(result.rows[0]) : undefined;
    });
  }

  async create(input: CreateShareLinkInput): Promise<ShareLink> {
    return withTenantContext(this.database, input.tenantId, async (tx) => {
      const result = await tx.execute<ShareLinkRow>(
        `INSERT INTO share_links (id, tenant_id, document_id, token_hash, permission, expires_at, max_downloads, created_by)
         VALUES ($1, $2, $3, $4, 'download', $5, $6, $7)
         RETURNING id, tenant_id, document_id, token_hash, permission, expires_at, max_downloads, download_count, revoked_at, created_by, created_at`,
        [
          input.id,
          input.tenantId,
          input.documentId,
          input.tokenHash,
          input.expiresAt,
          input.maxDownloads ?? null,
          input.createdBy
        ]
      );
      const row = result.rows[0];

      if (!row) {
        throw new Error("Share link insert did not return a row");
      }

      return fromShareLinkRow(row);
    });
  }

  async revoke(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined> {
    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ShareLinkRow>(
        `UPDATE share_links
         SET revoked_at = now()
         WHERE id = $1
         RETURNING id, tenant_id, document_id, token_hash, permission, expires_at, max_downloads, download_count, revoked_at, created_by, created_at`,
        [shareLinkId]
      );

      return result.rows[0] ? fromShareLinkRow(result.rows[0]) : undefined;
    });
  }

  async findByIdAndTokenHash(
    shareLinkId: string,
    tokenHash: string,
    tenantId?: string
  ): Promise<ShareLink | undefined> {
    if (!tenantId) {
      return this.database.transaction(async (tx) => {
        const result = await tx.execute<ShareLinkRow>(
          `SELECT id, tenant_id, document_id, token_hash, permission, expires_at, max_downloads, download_count, revoked_at, created_by, created_at
           FROM resolve_share_link_by_secret($1, $2)`,
          [shareLinkId, tokenHash]
        );

        return result.rows[0] ? fromShareLinkRow(result.rows[0]) : undefined;
      });
    }

    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ShareLinkRow>(
        `SELECT id, tenant_id, document_id, token_hash, permission, expires_at, max_downloads, download_count, revoked_at, created_by, created_at
         FROM share_links
         WHERE id = $1
           AND token_hash = $2`,
        [shareLinkId, tokenHash]
      );

      return result.rows[0] ? fromShareLinkRow(result.rows[0]) : undefined;
    });
  }

  async incrementDownload(tenantId: string, shareLinkId: string): Promise<ShareLink | undefined> {
    return withTenantContext(this.database, tenantId, async (tx) => {
      const result = await tx.execute<ShareLinkRow>(
        `UPDATE share_links
         SET download_count = download_count + 1
         WHERE id = $1
         RETURNING id, tenant_id, document_id, token_hash, permission, expires_at, max_downloads, download_count, revoked_at, created_by, created_at`,
        [shareLinkId]
      );

      return result.rows[0] ? fromShareLinkRow(result.rows[0]) : undefined;
    });
  }
}

type ShareLinkRow = {
  id: string;
  tenant_id: string;
  document_id: string;
  token_hash: string;
  permission: "download";
  expires_at: Date | string;
  max_downloads: number | null;
  download_count: number;
  revoked_at: Date | string | null;
  created_by: string;
  created_at: Date | string;
};

function fromShareLinkRow(row: ShareLinkRow): ShareLink {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    documentId: row.document_id,
    tokenHash: row.token_hash,
    permission: row.permission,
    expiresAt: new Date(row.expires_at),
    ...(row.max_downloads === null ? {} : { maxDownloads: row.max_downloads }),
    downloadCount: row.download_count,
    ...(row.revoked_at ? { revokedAt: new Date(row.revoked_at) } : {}),
    createdBy: row.created_by,
    createdAt: new Date(row.created_at)
  };
}
