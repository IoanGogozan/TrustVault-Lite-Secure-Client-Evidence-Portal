"use client";

import {
  Activity,
  Building2,
  CheckCircle2,
  FileUp,
  FolderPlus,
  KeyRound,
  Link2,
  LockKeyhole,
  LogOut,
  Play,
  ShieldCheck,
  UserRound
} from "lucide-react";
import { type FormEvent, useEffect, useMemo, useState } from "react";

type Role = "owner" | "admin" | "member" | "viewer" | "auditor";
type Classification = "public" | "internal" | "confidential" | "restricted";

type Membership = {
  tenantId: string;
  tenantName: string;
  tenantSlug: string;
  role: Role;
  mfaRequired: boolean;
};

type CurrentUser = {
  id: string;
  name: string;
  email: string;
  memberships: Membership[];
};

type Project = {
  id: string;
  tenantId: string;
  name: string;
  classification: Classification;
  createdBy: string;
  createdAt: string;
};

type DocumentRecord = {
  id: string;
  tenantId: string;
  projectId: string;
  title: string;
  classification: Classification;
  createdBy: string;
  createdAt: string;
};

type AuditEvent = {
  id: string;
  action: string;
  entityType: string;
  entityId?: string;
  actorType: string;
  result: "success" | "failure";
  createdAt: string;
};

type ShareLink = {
  id: string;
  tenantId: string;
  documentId: string;
  permission: "download";
  expiresAt: string;
  maxDownloads?: number;
  downloadCount: number;
  revokedAt?: string;
  createdBy: string;
  createdAt: string;
};

type DownloadMetadata = {
  documentId: string;
  versionId: string;
  originalFilename: string;
  mimeType: string;
  sizeBytes: number;
  expiresInSeconds: number;
  expiresAt: string;
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";

const securitySignals = [
  { label: "Session", value: "HttpOnly", icon: LockKeyhole },
  { label: "Tenant", value: "Scoped", icon: Building2 },
  { label: "Files", value: "Private", icon: ShieldCheck },
  { label: "Audit", value: "Live", icon: Activity }
];

export default function Home() {
  const [currentUser, setCurrentUser] = useState<CurrentUser | undefined>();
  const [selectedTenantId, setSelectedTenantId] = useState<string | undefined>();
  const [loginEmail, setLoginEmail] = useState("owner@acme.test");
  const [tenantName, setTenantName] = useState("");
  const [projectName, setProjectName] = useState("Vendor Evidence");
  const [projectClassification, setProjectClassification] = useState<Classification>("internal");
  const [documentTitle, setDocumentTitle] = useState("Vendor Security Review");
  const [selectedProjectId, setSelectedProjectId] = useState<string | undefined>();
  const [projects, setProjects] = useState<Project[]>([]);
  const [documents, setDocuments] = useState<DocumentRecord[]>([]);
  const [shareLinks, setShareLinks] = useState<ShareLink[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [downloadMetadata, setDownloadMetadata] = useState<DownloadMetadata | undefined>();
  const [lastShareToken, setLastShareToken] = useState<string | undefined>();
  const [statusMessage, setStatusMessage] = useState<string | undefined>();

  const selectedMembership = useMemo(
    () =>
      currentUser?.memberships.find((membership) => membership.tenantId === selectedTenantId) ??
      currentUser?.memberships[0],
    [currentUser?.memberships, selectedTenantId]
  );

  useEffect(() => {
    if (!selectedMembership) {
      setProjects([]);
      setDocuments([]);
      setAuditEvents([]);
      return;
    }

    void refreshWorkspace(selectedMembership.tenantId);
  }, [selectedMembership?.tenantId]);

  async function refreshCurrentUser() {
    const response = await fetch(`${apiBaseUrl}/me`, {
      credentials: "include"
    });

    if (!response.ok) {
      setCurrentUser(undefined);
      setSelectedTenantId(undefined);
      return;
    }

    const payload = (await response.json()) as {
      user: Omit<CurrentUser, "memberships">;
      memberships: Membership[];
    };
    const nextUser = {
      ...payload.user,
      memberships: payload.memberships
    };

    setCurrentUser(nextUser);
    setSelectedTenantId((currentTenantId) => currentTenantId ?? nextUser.memberships[0]?.tenantId);
  }

  async function refreshWorkspace(tenantId: string) {
    const [projectResponse, documentResponse, shareLinkResponse, auditResponse] = await Promise.all([
      apiGet<{ projects: Project[] }>("/projects", tenantId),
      apiGet<{ documents: DocumentRecord[] }>("/documents", tenantId),
      apiGet<{ shareLinks: ShareLink[] }>("/share-links", tenantId),
      apiGet<{ auditEvents: AuditEvent[] }>("/audit-events", tenantId)
    ]);

    if (projectResponse) {
      setProjects(projectResponse.projects);
      setSelectedProjectId((currentProjectId) => currentProjectId ?? projectResponse.projects[0]?.id);
    }

    if (documentResponse) {
      setDocuments(documentResponse.documents);
    }

    if (shareLinkResponse) {
      setShareLinks(shareLinkResponse.shareLinks);
    }

    setAuditEvents(auditResponse?.auditEvents ?? []);
  }

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatusMessage(undefined);

    const response = await fetch(`${apiBaseUrl}/auth/dev-login`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: loginEmail })
    });

    if (!response.ok) {
      setStatusMessage("Login failed");
      return;
    }

    await refreshCurrentUser();
  }

  async function handleLogout() {
    await fetch(`${apiBaseUrl}/auth/logout`, {
      method: "POST",
      credentials: "include"
    });
    setCurrentUser(undefined);
    setSelectedTenantId(undefined);
  }

  async function handleCreateTenant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatusMessage(undefined);

    const response = await fetch(`${apiBaseUrl}/tenants`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: tenantName })
    });

    if (!response.ok) {
      setStatusMessage("Organization could not be created");
      return;
    }

    setTenantName("");
    await refreshCurrentUser();
    setStatusMessage("Organization created");
  }

  async function handleCreateProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!selectedMembership) {
      return;
    }

    const response = await apiPost<{ project: Project }>("/projects", selectedMembership.tenantId, {
      name: projectName,
      classification: projectClassification
    });

    if (!response) {
      setStatusMessage("Project could not be created");
      return;
    }

    setSelectedProjectId(response.project.id);
    setStatusMessage("Project created");
    await refreshWorkspace(selectedMembership.tenantId);
  }

  async function handleCreateDocument(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!selectedMembership || !selectedProjectId) {
      return;
    }

    const documentResponse = await apiPost<{ document: DocumentRecord }>(
      "/documents",
      selectedMembership.tenantId,
      {
        title: documentTitle,
        projectId: selectedProjectId,
        classification: "confidential"
      }
    );

    if (!documentResponse) {
      setStatusMessage("Document could not be created");
      return;
    }

    const content = "%PDF-demo evidence";
    await apiPost(`/documents/${documentResponse.document.id}/versions`, selectedMembership.tenantId, {
      originalFilename: "vendor-evidence.pdf",
      mimeType: "application/pdf",
      sizeBytes: content.length,
      contentBase64: btoa(content)
    });
    await apiPost("/internal/scan-jobs/process-next", selectedMembership.tenantId, {});

    setStatusMessage("Document uploaded");
    await refreshWorkspace(selectedMembership.tenantId);
  }

  async function handlePrepareDownload(documentId: string) {
    if (!selectedMembership) {
      return;
    }

    const response = await apiGet<{ download: DownloadMetadata }>(
      `/documents/${documentId}/download`,
      selectedMembership.tenantId
    );

    if (!response) {
      setStatusMessage("Download is not available");
      return;
    }

    setDownloadMetadata(response.download);
    setStatusMessage("Download prepared");
    await refreshWorkspace(selectedMembership.tenantId);
  }

  async function handleCreateShareLink(documentId: string) {
    if (!selectedMembership) {
      return;
    }

    const response = await apiPost<{ shareLink: ShareLink; shareToken: string }>(
      "/share-links",
      selectedMembership.tenantId,
      {
        documentId,
        expiresInMinutes: 60,
        maxDownloads: 3
      }
    );

    if (!response) {
      setStatusMessage("Share link could not be created");
      return;
    }

    setLastShareToken(response.shareToken);
    setStatusMessage("Share link created");
    await refreshWorkspace(selectedMembership.tenantId);
  }

  async function handleUseShareLink() {
    if (!lastShareToken || !selectedMembership) {
      return;
    }

    const response = await fetch(`${apiBaseUrl}/public/share-links/${lastShareToken}`, {
      credentials: "omit"
    });

    if (!response.ok) {
      setStatusMessage("Share link is not available");
      await refreshWorkspace(selectedMembership.tenantId);
      return;
    }

    const payload = (await response.json()) as { download: DownloadMetadata };
    setDownloadMetadata(payload.download);
    setStatusMessage("Share link used");
    await refreshWorkspace(selectedMembership.tenantId);
  }

  async function handleRevokeShareLink(shareLinkId: string) {
    if (!selectedMembership) {
      return;
    }

    const response = await apiDelete(`/share-links/${shareLinkId}`, selectedMembership.tenantId);

    if (!response) {
      setStatusMessage("Share link could not be revoked");
      return;
    }

    setStatusMessage("Share link revoked");
    await refreshWorkspace(selectedMembership.tenantId);
  }

  async function apiGet<T>(path: string, tenantId: string): Promise<T | undefined> {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      credentials: "include",
      headers: { "X-Tenant-Id": tenantId }
    });

    return response.ok ? ((await response.json()) as T) : undefined;
  }

  async function apiPost<T>(path: string, tenantId: string, body: unknown): Promise<T | undefined> {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-Tenant-Id": tenantId
      },
      body: JSON.stringify(body)
    });

    return response.ok ? ((await response.json()) as T) : undefined;
  }

  async function apiDelete(path: string, tenantId: string): Promise<boolean> {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      method: "DELETE",
      credentials: "include",
      headers: { "X-Tenant-Id": tenantId }
    });

    return response.ok;
  }

  if (!currentUser) {
    return (
      <main className="login-shell">
        <form className="login-panel" aria-label="Demo login" onSubmit={handleLogin}>
          <div className="brand-mark">
            <ShieldCheck aria-hidden="true" />
          </div>
          <div>
            <h1>TrustVault Lite</h1>
            <p>Secure client evidence portal</p>
          </div>
          <label className="field">
            <span>Email</span>
            <input
              value={loginEmail}
              onChange={(event) => setLoginEmail(event.target.value)}
              type="email"
              autoComplete="email"
            />
          </label>
          {statusMessage ? <p className="status-message">{statusMessage}</p> : null}
          <button className="primary-action" type="submit">
            <KeyRound aria-hidden="true" />
            Demo login
          </button>
        </form>
      </main>
    );
  }

  if (!selectedMembership) {
    return (
      <main className="login-shell">
        <section className="login-panel" aria-label="No tenant access">
          <div className="brand-mark">
            <ShieldCheck aria-hidden="true" />
          </div>
          <div>
            <h1>No active tenant</h1>
            <p>Create an organization or accept an invitation to continue.</p>
          </div>
          <button className="primary-action" type="button" onClick={handleLogout}>
            <LogOut aria-hidden="true" />
            Log out
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="sidebar-brand">
          <ShieldCheck aria-hidden="true" />
          <span>TrustVault</span>
        </div>
        <nav>
          <a className="nav-item active" href="#evidence">
            <FileUp aria-hidden="true" />
            Evidence
          </a>
          <a className="nav-item" href="#audit">
            <Activity aria-hidden="true" />
            Audit
          </a>
          <a className="nav-item" href="#organization">
            <Building2 aria-hidden="true" />
            Organization
          </a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Tenant workspace</p>
            <h1>{selectedMembership.tenantName}</h1>
          </div>
          <div className="topbar-actions">
            <label>
              <span>Tenant</span>
              <select
                value={selectedMembership.tenantId}
                onChange={(event) => setSelectedTenantId(event.target.value)}
              >
                {currentUser.memberships.map((membership) => (
                  <option key={membership.tenantId} value={membership.tenantId}>
                    {membership.tenantName}
                  </option>
                ))}
              </select>
            </label>
            <button className="icon-action" type="button" onClick={handleLogout}>
              <LogOut aria-hidden="true" />
              <span className="sr-only">Log out</span>
            </button>
          </div>
        </header>

        <section className="summary-grid" aria-label="Security summary">
          {securitySignals.map((signal) => {
            const Icon = signal.icon;

            return (
              <article className="metric" key={signal.label}>
                <Icon aria-hidden="true" />
                <div>
                  <span>{signal.label}</span>
                  <strong>{signal.value}</strong>
                </div>
              </article>
            );
          })}
        </section>

        <section className="content-grid" id="evidence">
          <article className="panel">
            <div className="panel-heading">
              <h2>Create project</h2>
              <FolderPlus aria-hidden="true" />
            </div>
            <form className="stack-form" onSubmit={handleCreateProject}>
              <label className="field">
                <span>Project name</span>
                <input
                  value={projectName}
                  onChange={(event) => setProjectName(event.target.value)}
                />
              </label>
              <label className="field">
                <span>Classification</span>
                <select
                  value={projectClassification}
                  onChange={(event) =>
                    setProjectClassification(event.target.value as Classification)
                  }
                >
                  <option value="public">Public</option>
                  <option value="internal">Internal</option>
                  <option value="confidential">Confidential</option>
                  <option value="restricted">Restricted</option>
                </select>
              </label>
              <button className="secondary-action" type="submit">
                <FolderPlus aria-hidden="true" />
                Create project
              </button>
            </form>
          </article>

          <article className="panel">
            <div className="panel-heading">
              <h2>Upload document</h2>
              <FileUp aria-hidden="true" />
            </div>
            <form className="stack-form" onSubmit={handleCreateDocument}>
              <label className="field">
                <span>Project</span>
                <select
                  value={selectedProjectId ?? ""}
                  onChange={(event) => setSelectedProjectId(event.target.value)}
                >
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Document title</span>
                <input
                  value={documentTitle}
                  onChange={(event) => setDocumentTitle(event.target.value)}
                />
              </label>
              <button className="secondary-action" type="submit" disabled={!selectedProjectId}>
                <FileUp aria-hidden="true" />
                Upload PDF
              </button>
              {statusMessage ? <p className="status-message">{statusMessage}</p> : null}
            </form>
          </article>
        </section>

        <section className="content-grid">
          <article className="panel">
            <div className="panel-heading">
              <h2>Projects</h2>
              <Building2 aria-hidden="true" />
            </div>
            <div className="record-list">
              {projects.map((project) => (
                <button
                  className="record-row"
                  key={project.id}
                  type="button"
                  onClick={() => setSelectedProjectId(project.id)}
                >
                  <span>{project.name}</span>
                  <strong>{formatClassification(project.classification)}</strong>
                </button>
              ))}
            </div>
          </article>

          <article className="panel">
            <div className="panel-heading">
              <h2>Documents</h2>
              <CheckCircle2 aria-hidden="true" />
            </div>
            <div className="record-list">
              {documents.map((document) => (
                <div className="record-row passive document-row" key={document.id}>
                  <div>
                    <span>{document.title}</span>
                    <small>{formatClassification(document.classification)}</small>
                  </div>
                  <button
                    className="compact-action"
                    type="button"
                    onClick={() => void handlePrepareDownload(document.id)}
                  >
                    Prepare download
                  </button>
                  <button
                    className="compact-action"
                    type="button"
                    onClick={() => void handleCreateShareLink(document.id)}
                  >
                    Create link
                  </button>
                </div>
              ))}
            </div>
            {downloadMetadata ? (
              <dl className="details compact">
                <div>
                  <dt>File</dt>
                  <dd>{downloadMetadata.originalFilename}</dd>
                </div>
                <div>
                  <dt>Expires</dt>
                  <dd>{new Date(downloadMetadata.expiresAt).toLocaleTimeString()}</dd>
                </div>
              </dl>
            ) : null}
          </article>
        </section>

        <section className="content-grid">
          <article className="panel">
            <div className="panel-heading">
              <h2>Share links</h2>
              <Link2 aria-hidden="true" />
            </div>
            {lastShareToken ? (
              <div className="token-box">
                <span>One-time token</span>
                <code>{lastShareToken}</code>
                <button className="compact-action" type="button" onClick={() => void handleUseShareLink()}>
                  Use public link
                </button>
              </div>
            ) : null}
            <div className="record-list">
              {shareLinks.map((shareLink) => (
                <div className="record-row passive document-row" key={shareLink.id}>
                  <div>
                    <span>{shareLink.revokedAt ? "Revoked link" : "Active link"}</span>
                    <small>
                      {shareLink.downloadCount}
                      {shareLink.maxDownloads ? `/${shareLink.maxDownloads}` : ""} downloads
                    </small>
                  </div>
                  <button
                    className="compact-action"
                    type="button"
                    disabled={Boolean(shareLink.revokedAt)}
                    onClick={() => void handleRevokeShareLink(shareLink.id)}
                  >
                    Revoke
                  </button>
                </div>
              ))}
            </div>
          </article>

          <article className="panel" id="audit">
            <div className="panel-heading">
              <h2>Audit events</h2>
              <Activity aria-hidden="true" />
            </div>
            <div className="audit-list">
              {auditEvents.map((event) => (
                <div className="audit-row" key={event.id}>
                  <span className={`result-dot ${event.result}`} />
                  <div>
                    <strong>{event.action}</strong>
                    <span>{event.entityType}</span>
                  </div>
                  <time>{new Date(event.createdAt).toLocaleTimeString()}</time>
                </div>
              ))}
            </div>
          </article>

          <article className="panel" id="organization">
            <div className="panel-heading">
              <h2>Create organization</h2>
              <Building2 aria-hidden="true" />
            </div>
            <form className="stack-form" onSubmit={handleCreateTenant}>
              <label className="field">
                <span>Organization name</span>
                <input
                  value={tenantName}
                  onChange={(event) => setTenantName(event.target.value)}
                  placeholder="Northwind Security"
                />
              </label>
              <button className="secondary-action" type="submit">
                <Play aria-hidden="true" />
                Create
              </button>
            </form>
            <dl className="details compact">
              <div>
                <dt>User</dt>
                <dd>{currentUser.name}</dd>
              </div>
              <div>
                <dt>Role</dt>
                <dd>{formatRole(selectedMembership.role)}</dd>
              </div>
            </dl>
          </article>
        </section>
      </section>
    </main>
  );
}

function formatRole(role: Role): string {
  return role
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatClassification(classification: Classification): string {
  return classification.charAt(0).toUpperCase() + classification.slice(1);
}
