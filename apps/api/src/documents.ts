import { withTenantContext, type DatabasePool } from "@trustvault/database";
import { randomUUID } from "node:crypto";
import type {
  AppStore,
  Document,
  DocumentClassification,
  DocumentVersion,
  MembershipRole
} from "./domain.js";
import { canSeeProject } from "./projects.js";

export type DocumentReadScope = {
  tenantId: string;
  role: MembershipRole;
  projectIds?: readonly string[];
};

export type CreateDocumentInput = {
  tenantId: string;
  projectId: string;
  title: string;
  classification: DocumentClassification;
  createdBy: string;
};

export type UploadDocumentVersionInput = {
  tenantId: string;
  documentId: string;
  storageKey: string;
  originalFilename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  uploadedBy: string;
};

export type DocumentRepository = {
  list(scope: DocumentReadScope): Promise<Document[]>;
  findVisibleById(scope: DocumentReadScope, documentId: string): Promise<Document | undefined>;
  findByIdForAuthorization?(documentId: string): Promise<Document | undefined>;
  create(input: CreateDocumentInput): Promise<Document>;
  softDelete(scope: DocumentReadScope, documentId: string): Promise<boolean>;
  uploadVersion(input: UploadDocumentVersionInput): Promise<DocumentVersion>;
  updateScanStatus(
    scope: DocumentReadScope,
    versionId: string,
    scanStatus: "clean" | "blocked"
  ): Promise<DocumentVersion | undefined>;
  findCurrentVersionForDownload(
    scope: DocumentReadScope,
    documentId: string
  ): Promise<DocumentVersion | undefined>;
};

export class InMemoryDocumentRepository implements DocumentRepository {
  constructor(private readonly store: AppStore) {}

  async list(scope: DocumentReadScope): Promise<Document[]> {
    return this.store.documents
      .filter((document) => document.tenantId === scope.tenantId && !document.deletedAt)
      .filter((document) => canSeeProject(scope, document.projectId));
  }

  async findVisibleById(
    scope: DocumentReadScope,
    documentId: string
  ): Promise<Document | undefined> {
    return this.store.documents.find(
      (document) =>
        document.id === documentId &&
        !document.deletedAt &&
        document.tenantId === scope.tenantId &&
        canSeeProject(scope, document.projectId)
    );
  }

  async findByIdForAuthorization(documentId: string): Promise<Document | undefined> {
    return this.store.documents.find(
      (document) => document.id === documentId && !document.deletedAt
    );
  }

  async create(input: CreateDocumentInput): Promise<Document> {
    const document = {
      id: `document_${randomUUID()}`,
      tenantId: input.tenantId,
      projectId: input.projectId,
      title: input.title,
      classification: input.classification,
      storageKey: `${input.tenantId}/documents/${randomUUID()}`,
      currentVersionId: `version_${randomUUID()}`,
      createdBy: input.createdBy,
      createdAt: new Date()
    };

    this.store.documents.push(document);

    return document;
  }

  async softDelete(scope: DocumentReadScope, documentId: string): Promise<boolean> {
    const document = await this.findVisibleById(scope, documentId);

    if (!document) {
      return false;
    }

    document.deletedAt = new Date();

    return true;
  }

  async uploadVersion(input: UploadDocumentVersionInput): Promise<DocumentVersion> {
    const document = this.store.documents.find(
      (candidate) => candidate.id === input.documentId && candidate.tenantId === input.tenantId
    );

    if (!document) {
      throw new Error("Document not found for version upload");
    }

    const version = {
      id: `version_${randomUUID()}`,
      tenantId: input.tenantId,
      documentId: input.documentId,
      storageKey: input.storageKey,
      originalFilename: input.originalFilename,
      mimeType: input.mimeType,
      sizeBytes: input.sizeBytes,
      sha256: input.sha256,
      scanStatus: "pending_scan" as const,
      uploadedBy: input.uploadedBy,
      createdAt: new Date()
    };

    this.store.documentVersions.push(version);
    document.currentVersionId = version.id;
    document.storageKey = version.storageKey;

    return version;
  }

  async updateScanStatus(
    scope: DocumentReadScope,
    versionId: string,
    scanStatus: "clean" | "blocked"
  ): Promise<DocumentVersion | undefined> {
    const version = this.store.documentVersions.find(
      (candidate) => candidate.id === versionId && candidate.tenantId === scope.tenantId
    );

    if (!version) {
      return undefined;
    }

    version.scanStatus = scanStatus;

    return version;
  }

  async findCurrentVersionForDownload(
    scope: DocumentReadScope,
    documentId: string
  ): Promise<DocumentVersion | undefined> {
    const document = await this.findVisibleById(scope, documentId);

    if (!document) {
      return undefined;
    }

    return this.store.documentVersions.find(
      (version) =>
        version.id === document.currentVersionId &&
        version.tenantId === scope.tenantId &&
        version.documentId === document.id
    );
  }
}

export class PostgresDocumentRepository implements DocumentRepository {
  constructor(private readonly database: DatabasePool) {}

  async list(scope: DocumentReadScope): Promise<Document[]> {
    return withTenantContext(this.database, scope.tenantId, async (tx) => {
      const result = await tx.execute<DocumentRow>(
        `SELECT id, tenant_id, project_id, title, classification, current_version_id, created_by, deleted_at, created_at
         FROM documents
         WHERE deleted_at IS NULL
         ORDER BY created_at DESC`
      );

      return result.rows.map(fromDocumentRow).filter((document) => canSeeProject(scope, document.projectId));
    });
  }

  async findVisibleById(
    scope: DocumentReadScope,
    documentId: string
  ): Promise<Document | undefined> {
    return withTenantContext(this.database, scope.tenantId, async (tx) => {
      const result = await tx.execute<DocumentRow>(
        `SELECT id, tenant_id, project_id, title, classification, current_version_id, created_by, deleted_at, created_at
         FROM documents
         WHERE id = $1 AND deleted_at IS NULL`,
        [documentId]
      );
      const document = result.rows[0] ? fromDocumentRow(result.rows[0]) : undefined;

      return document && canSeeProject(scope, document.projectId) ? document : undefined;
    });
  }

  async create(input: CreateDocumentInput): Promise<Document> {
    return withTenantContext(this.database, input.tenantId, async (tx) => {
      const result = await tx.execute<DocumentRow>(
        `INSERT INTO documents (tenant_id, project_id, title, classification, created_by)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, tenant_id, project_id, title, classification, current_version_id, created_by, deleted_at, created_at`,
        [input.tenantId, input.projectId, input.title, input.classification, input.createdBy]
      );

      const row = result.rows[0];

      if (!row) {
        throw new Error("Document insert did not return a row");
      }

      return fromDocumentRow(row);
    });
  }

  async softDelete(scope: DocumentReadScope, documentId: string): Promise<boolean> {
    return withTenantContext(this.database, scope.tenantId, async (tx) => {
      const result = await tx.execute(
        `UPDATE documents
         SET deleted_at = now()
         WHERE id = $1 AND deleted_at IS NULL`,
        [documentId]
      );

      return result.rowCount > 0;
    });
  }

  async uploadVersion(input: UploadDocumentVersionInput): Promise<DocumentVersion> {
    return withTenantContext(this.database, input.tenantId, async (tx) => {
      const versionResult = await tx.execute<DocumentVersionRow>(
        `INSERT INTO document_versions (
           tenant_id,
           document_id,
           storage_key,
           original_filename,
           mime_type,
           size_bytes,
           sha256,
           uploaded_by
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, tenant_id, document_id, storage_key, original_filename, mime_type, size_bytes, sha256, scan_status, uploaded_by, created_at`,
        [
          input.tenantId,
          input.documentId,
          input.storageKey,
          input.originalFilename,
          input.mimeType,
          input.sizeBytes,
          input.sha256,
          input.uploadedBy
        ]
      );
      const row = versionResult.rows[0];

      if (!row) {
        throw new Error("Document version insert did not return a row");
      }

      const documentUpdate = await tx.execute(
        `UPDATE documents
         SET current_version_id = $1
         WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL`,
        [row.id, input.documentId, input.tenantId]
      );

      if (documentUpdate.rowCount === 0) {
        throw new Error("Document version upload did not update a document");
      }

      return fromDocumentVersionRow(row);
    });
  }

  async updateScanStatus(
    scope: DocumentReadScope,
    versionId: string,
    scanStatus: "clean" | "blocked"
  ): Promise<DocumentVersion | undefined> {
    return withTenantContext(this.database, scope.tenantId, async (tx) => {
      const result = await tx.execute<DocumentVersionRow>(
        `UPDATE document_versions
         SET scan_status = $1
         WHERE id = $2
         RETURNING id, tenant_id, document_id, storage_key, original_filename, mime_type, size_bytes, sha256, scan_status, uploaded_by, created_at`,
        [scanStatus, versionId]
      );
      const version = result.rows[0] ? fromDocumentVersionRow(result.rows[0]) : undefined;

      if (!version) {
        return undefined;
      }

      const document = await this.findVisibleById(scope, version.documentId);

      return document ? version : undefined;
    });
  }

  async findCurrentVersionForDownload(
    scope: DocumentReadScope,
    documentId: string
  ): Promise<DocumentVersion | undefined> {
    return withTenantContext(this.database, scope.tenantId, async (tx) => {
      const result = await tx.execute<DocumentVersionRow>(
        `SELECT
           document_versions.id,
           document_versions.tenant_id,
           document_versions.document_id,
           document_versions.storage_key,
           document_versions.original_filename,
           document_versions.mime_type,
           document_versions.size_bytes,
           document_versions.sha256,
           document_versions.scan_status,
           document_versions.uploaded_by,
           document_versions.created_at
         FROM document_versions
         INNER JOIN documents
           ON documents.current_version_id = document_versions.id
          AND documents.id = document_versions.document_id
         WHERE documents.id = $1
           AND documents.deleted_at IS NULL`,
        [documentId]
      );
      const version = result.rows[0] ? fromDocumentVersionRow(result.rows[0]) : undefined;
      const document = version ? await this.findVisibleById(scope, version.documentId) : undefined;

      return document ? version : undefined;
    });
  }
}

type DocumentRow = {
  id: string;
  tenant_id: string;
  project_id: string;
  title: string;
  classification: DocumentClassification;
  current_version_id: string | null;
  created_by: string;
  deleted_at: Date | string | null;
  created_at: Date | string;
};

type DocumentVersionRow = {
  id: string;
  tenant_id: string;
  document_id: string;
  storage_key: string;
  original_filename: string;
  mime_type: string;
  size_bytes: number | string;
  sha256: string;
  scan_status: DocumentVersion["scanStatus"];
  uploaded_by: string;
  created_at: Date | string;
};

function fromDocumentRow(row: DocumentRow): Document {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    projectId: row.project_id,
    title: row.title,
    classification: row.classification,
    storageKey: "[REDACTED]",
    currentVersionId: row.current_version_id ?? "",
    createdBy: row.created_by,
    ...(row.deleted_at ? { deletedAt: new Date(row.deleted_at) } : {}),
    createdAt: new Date(row.created_at)
  };
}

function fromDocumentVersionRow(row: DocumentVersionRow): DocumentVersion {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    documentId: row.document_id,
    storageKey: row.storage_key,
    originalFilename: row.original_filename,
    mimeType: row.mime_type,
    sizeBytes: Number(row.size_bytes),
    sha256: row.sha256,
    scanStatus: row.scan_status,
    uploadedBy: row.uploaded_by,
    createdAt: new Date(row.created_at)
  };
}
