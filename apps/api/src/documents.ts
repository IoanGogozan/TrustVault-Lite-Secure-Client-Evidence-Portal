import { withTenantContext, type DatabasePool } from "@trustvault/database";
import { randomUUID } from "node:crypto";
import type {
  AppStore,
  Document,
  DocumentClassification,
  MembershipRole
} from "./domain.js";

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

export type DocumentRepository = {
  list(scope: DocumentReadScope): Promise<Document[]>;
  findVisibleById(scope: DocumentReadScope, documentId: string): Promise<Document | undefined>;
  findByIdForAuthorization?(documentId: string): Promise<Document | undefined>;
  create(input: CreateDocumentInput): Promise<Document>;
  softDelete(scope: DocumentReadScope, documentId: string): Promise<boolean>;
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
}

function canSeeProject(scope: DocumentReadScope, projectId: string): boolean {
  if (scope.role === "owner" || scope.role === "admin" || scope.role === "auditor") {
    return true;
  }

  return scope.projectIds?.includes(projectId) ?? false;
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
