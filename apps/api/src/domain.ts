import type { AuditEvent } from "@trustvault/audit";

export type UserStatus = "active" | "disabled";
export type MembershipRole = "owner" | "admin" | "member" | "viewer" | "auditor";
export type MembershipStatus = "active" | "invited" | "suspended";
export type InvitationStatus = "pending" | "accepted" | "revoked";
export type DocumentClassification = "public" | "internal" | "confidential" | "restricted";
export type ScanStatus = "pending_scan" | "clean" | "blocked";
export type ScanJobStatus = "queued" | "processing" | "completed" | "failed";

export type User = {
  id: string;
  email: string;
  name: string;
  identityProviderSubject: string;
  status: UserStatus;
  createdAt: Date;
};

export type Tenant = {
  id: string;
  name: string;
  slug: string;
  plan: "demo" | "team";
  createdAt: Date;
};

export type Membership = {
  id: string;
  tenantId: string;
  userId: string;
  role: MembershipRole;
  status: MembershipStatus;
  mfaRequired: boolean;
  projectIds?: string[];
  createdAt: Date;
};

export type Project = {
  id: string;
  tenantId: string;
  name: string;
  classification: DocumentClassification;
  createdBy: string;
  createdAt: Date;
};

export type Document = {
  id: string;
  tenantId: string;
  projectId: string;
  title: string;
  classification: DocumentClassification;
  storageKey: string;
  currentVersionId: string;
  createdBy: string;
  deletedAt?: Date;
  createdAt: Date;
};

export type DocumentVersion = {
  id: string;
  tenantId: string;
  documentId: string;
  storageKey: string;
  originalFilename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  scanStatus: ScanStatus;
  uploadedBy: string;
  createdAt: Date;
};

export type ScanJob = {
  id: string;
  tenantId: string;
  documentId: string;
  versionId: string;
  storageKey: string;
  status: ScanJobStatus;
  queuedBy: string;
  attempts: number;
  createdAt: Date;
  updatedAt: Date;
};

export type Session = {
  id: string;
  userId: string;
  createdAt: Date;
  revokedAt?: Date;
};

export type Invitation = {
  id: string;
  tenantId: string;
  email: string;
  role: MembershipRole;
  tokenHash: string;
  status: InvitationStatus;
  invitedBy: string;
  acceptedBy?: string;
  expiresAt: Date;
  createdAt: Date;
};

export type AppStore = {
  users: User[];
  tenants: Tenant[];
  memberships: Membership[];
  projects: Project[];
  documents: Document[];
  documentVersions: DocumentVersion[];
  scanJobs: ScanJob[];
  storageObjects: Record<string, string>;
  invitations: Invitation[];
  auditEvents: AuditEvent[];
  sessions: Session[];
};

const now = new Date("2026-05-03T00:00:00.000Z");

export function createDemoStore(): AppStore {
  return {
    users: [
      {
        id: "user_owner_acme",
        email: "owner@acme.test",
        name: "Acme Owner",
        identityProviderSubject: "oidc|acme-owner",
        status: "active",
        createdAt: now
      },
      {
        id: "user_viewer_acme",
        email: "viewer@acme.test",
        name: "Acme Viewer",
        identityProviderSubject: "oidc|acme-viewer",
        status: "active",
        createdAt: now
      },
      {
        id: "user_admin_acme",
        email: "admin@acme.test",
        name: "Acme Admin",
        identityProviderSubject: "oidc|acme-admin",
        status: "active",
        createdAt: now
      },
      {
        id: "user_member_acme",
        email: "member@acme.test",
        name: "Acme Member",
        identityProviderSubject: "oidc|acme-member",
        status: "active",
        createdAt: now
      },
      {
        id: "user_auditor_acme",
        email: "auditor@acme.test",
        name: "Acme Auditor",
        identityProviderSubject: "oidc|acme-auditor",
        status: "active",
        createdAt: now
      },
      {
        id: "user_owner_globex",
        email: "owner@globex.test",
        name: "Globex Owner",
        identityProviderSubject: "oidc|globex-owner",
        status: "active",
        createdAt: now
      }
    ],
    tenants: [
      {
        id: "tenant_acme",
        name: "Acme Corp",
        slug: "acme",
        plan: "demo",
        createdAt: now
      },
      {
        id: "tenant_globex",
        name: "Globex",
        slug: "globex",
        plan: "demo",
        createdAt: now
      }
    ],
    memberships: [
      {
        id: "membership_acme_owner",
        tenantId: "tenant_acme",
        userId: "user_owner_acme",
        role: "owner",
        status: "active",
        mfaRequired: true,
        createdAt: now
      },
      {
        id: "membership_acme_viewer",
        tenantId: "tenant_acme",
        userId: "user_viewer_acme",
        role: "viewer",
        status: "active",
        mfaRequired: true,
        projectIds: ["project_acme_soc2"],
        createdAt: now
      },
      {
        id: "membership_acme_admin",
        tenantId: "tenant_acme",
        userId: "user_admin_acme",
        role: "admin",
        status: "active",
        mfaRequired: true,
        createdAt: now
      },
      {
        id: "membership_acme_member",
        tenantId: "tenant_acme",
        userId: "user_member_acme",
        role: "member",
        status: "active",
        mfaRequired: true,
        projectIds: ["project_acme_soc2"],
        createdAt: now
      },
      {
        id: "membership_acme_auditor",
        tenantId: "tenant_acme",
        userId: "user_auditor_acme",
        role: "auditor",
        status: "active",
        mfaRequired: true,
        createdAt: now
      },
      {
        id: "membership_globex_owner",
        tenantId: "tenant_globex",
        userId: "user_owner_globex",
        role: "owner",
        status: "active",
        mfaRequired: true,
        createdAt: now
      }
    ],
    projects: [
      {
        id: "project_acme_soc2",
        tenantId: "tenant_acme",
        name: "SOC 2 Evidence",
        classification: "confidential",
        createdBy: "user_owner_acme",
        createdAt: now
      },
      {
        id: "project_globex_legal",
        tenantId: "tenant_globex",
        name: "Legal Review",
        classification: "restricted",
        createdBy: "system",
        createdAt: now
      }
    ],
    documents: [
      {
        id: "document_acme_policy",
        tenantId: "tenant_acme",
        projectId: "project_acme_soc2",
        title: "Security Policy",
        classification: "confidential",
        storageKey: "tenant_acme/documents/security-policy.pdf",
        currentVersionId: "version_acme_policy_1",
        createdBy: "user_owner_acme",
        createdAt: now
      },
      {
        id: "document_acme_restricted",
        tenantId: "tenant_acme",
        projectId: "project_acme_soc2",
        title: "Restricted Board Report",
        classification: "restricted",
        storageKey: "tenant_acme/documents/restricted-board-report.pdf",
        currentVersionId: "version_acme_restricted_1",
        createdBy: "user_owner_acme",
        createdAt: now
      },
      {
        id: "document_globex_contract",
        tenantId: "tenant_globex",
        projectId: "project_globex_legal",
        title: "Globex Contract",
        classification: "restricted",
        storageKey: "tenant_globex/documents/contract.pdf",
        currentVersionId: "version_globex_contract_1",
        createdBy: "system",
        createdAt: now
      }
    ],
    documentVersions: [
      {
        id: "version_acme_policy_1",
        tenantId: "tenant_acme",
        documentId: "document_acme_policy",
        storageKey: "tenant_acme/documents/security-policy.pdf",
        originalFilename: "security-policy.pdf",
        mimeType: "application/pdf",
        sizeBytes: 5,
        sha256: "seeded",
        scanStatus: "clean",
        uploadedBy: "user_owner_acme",
        createdAt: now
      },
      {
        id: "version_acme_restricted_1",
        tenantId: "tenant_acme",
        documentId: "document_acme_restricted",
        storageKey: "tenant_acme/documents/restricted-board-report.pdf",
        originalFilename: "restricted-board-report.pdf",
        mimeType: "application/pdf",
        sizeBytes: 5,
        sha256: "seeded",
        scanStatus: "clean",
        uploadedBy: "user_owner_acme",
        createdAt: now
      }
    ],
    scanJobs: [],
    storageObjects: {},
    invitations: [],
    auditEvents: [],
    sessions: []
  };
}
