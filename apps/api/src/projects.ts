import { withTenantContext, type DatabasePool } from "@trustvault/database";
import { randomUUID } from "node:crypto";
import type {
  AppStore,
  DocumentClassification,
  MembershipRole,
  Project
} from "./domain.js";

export type ProjectReadScope = {
  tenantId: string;
  role: MembershipRole;
  projectIds?: readonly string[];
};

export type CreateProjectInput = {
  tenantId: string;
  name: string;
  classification: DocumentClassification;
  createdBy: string;
};

export type UpdateProjectInput = {
  name?: string;
  classification?: DocumentClassification;
};

export type ProjectRepository = {
  list(scope: ProjectReadScope): Promise<Project[]>;
  findVisibleById(scope: ProjectReadScope, projectId: string): Promise<Project | undefined>;
  findByIdForAuthorization?(projectId: string): Promise<Project | undefined>;
  create(input: CreateProjectInput): Promise<Project>;
  update(
    scope: ProjectReadScope,
    projectId: string,
    input: UpdateProjectInput
  ): Promise<Project | undefined>;
};

export class InMemoryProjectRepository implements ProjectRepository {
  constructor(private readonly store: AppStore) {}

  async list(scope: ProjectReadScope): Promise<Project[]> {
    return this.store.projects
      .filter((project) => project.tenantId === scope.tenantId)
      .filter((project) => canSeeProject(scope, project.id));
  }

  async findVisibleById(
    scope: ProjectReadScope,
    projectId: string
  ): Promise<Project | undefined> {
    return this.store.projects.find(
      (project) =>
        project.id === projectId &&
        project.tenantId === scope.tenantId &&
        canSeeProject(scope, project.id)
    );
  }

  async findByIdForAuthorization(projectId: string): Promise<Project | undefined> {
    return this.store.projects.find((project) => project.id === projectId);
  }

  async create(input: CreateProjectInput): Promise<Project> {
    const project = {
      id: `project_${randomUUID()}`,
      tenantId: input.tenantId,
      name: input.name,
      classification: input.classification,
      createdBy: input.createdBy,
      createdAt: new Date()
    };

    this.store.projects.push(project);

    return project;
  }

  async update(
    scope: ProjectReadScope,
    projectId: string,
    input: UpdateProjectInput
  ): Promise<Project | undefined> {
    const project = await this.findVisibleById(scope, projectId);

    if (!project) {
      return undefined;
    }

    if (input.name) {
      project.name = input.name;
    }

    if (input.classification) {
      project.classification = input.classification;
    }

    return project;
  }
}

export class PostgresProjectRepository implements ProjectRepository {
  constructor(private readonly database: DatabasePool) {}

  async list(scope: ProjectReadScope): Promise<Project[]> {
    return withTenantContext(this.database, scope.tenantId, async (tx) => {
      const result = await tx.execute<ProjectRow>(
        `SELECT id, tenant_id, name, classification, created_by, created_at
         FROM projects
         ORDER BY created_at DESC`
      );

      return result.rows.map(fromProjectRow).filter((project) => canSeeProject(scope, project.id));
    });
  }

  async findVisibleById(
    scope: ProjectReadScope,
    projectId: string
  ): Promise<Project | undefined> {
    return withTenantContext(this.database, scope.tenantId, async (tx) => {
      const result = await tx.execute<ProjectRow>(
        `SELECT id, tenant_id, name, classification, created_by, created_at
         FROM projects
         WHERE id = $1`,
        [projectId]
      );
      const project = result.rows[0] ? fromProjectRow(result.rows[0]) : undefined;

      return project && canSeeProject(scope, project.id) ? project : undefined;
    });
  }

  async create(input: CreateProjectInput): Promise<Project> {
    return withTenantContext(this.database, input.tenantId, async (tx) => {
      const result = await tx.execute<ProjectRow>(
        `INSERT INTO projects (tenant_id, name, classification, created_by)
         VALUES ($1, $2, $3, $4)
         RETURNING id, tenant_id, name, classification, created_by, created_at`,
        [input.tenantId, input.name, input.classification, input.createdBy]
      );
      const row = result.rows[0];

      if (!row) {
        throw new Error("Project insert did not return a row");
      }

      return fromProjectRow(row);
    });
  }

  async update(
    scope: ProjectReadScope,
    projectId: string,
    input: UpdateProjectInput
  ): Promise<Project | undefined> {
    return withTenantContext(this.database, scope.tenantId, async (tx) => {
      const current = await this.findVisibleById(scope, projectId);

      if (!current) {
        return undefined;
      }

      const result = await tx.execute<ProjectRow>(
        `UPDATE projects
         SET name = $1, classification = $2
         WHERE id = $3
         RETURNING id, tenant_id, name, classification, created_by, created_at`,
        [
          input.name ?? current.name,
          input.classification ?? current.classification,
          projectId
        ]
      );

      return result.rows[0] ? fromProjectRow(result.rows[0]) : undefined;
    });
  }
}

export function canSeeProject(scope: ProjectReadScope, projectId: string): boolean {
  if (scope.role === "owner" || scope.role === "admin" || scope.role === "auditor") {
    return true;
  }

  return scope.projectIds?.includes(projectId) ?? false;
}

type ProjectRow = {
  id: string;
  tenant_id: string;
  name: string;
  classification: DocumentClassification;
  created_by: string;
  created_at: Date | string;
};

function fromProjectRow(row: ProjectRow): Project {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    classification: row.classification,
    createdBy: row.created_by,
    createdAt: new Date(row.created_at)
  };
}
