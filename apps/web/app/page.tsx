"use client";

import {
  Activity,
  Building2,
  CheckCircle2,
  KeyRound,
  LockKeyhole,
  LogOut,
  ShieldCheck,
  UserRound
} from "lucide-react";
import { type FormEvent, useMemo, useState } from "react";

type Role = "owner" | "admin" | "member" | "viewer" | "auditor";

type Membership = {
  tenantId: string;
  tenantName: string;
  tenantSlug: string;
  role: Role;
  mfaRequired: boolean;
};

type CurrentUser = {
  name: string;
  email: string;
  memberships: Membership[];
};

const securitySignals = [
  {
    label: "Secure session",
    value: "HttpOnly cookie",
    icon: LockKeyhole
  },
  {
    label: "Tenant context",
    value: "Membership verified",
    icon: Building2
  },
  {
    label: "MFA policy",
    value: "Required",
    icon: ShieldCheck
  },
  {
    label: "Audit trail",
    value: "Enabled",
    icon: Activity
  }
];

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";

export default function Home() {
  const [currentUser, setCurrentUser] = useState<CurrentUser | undefined>();
  const [selectedTenantId, setSelectedTenantId] = useState<string | undefined>();
  const [loginEmail, setLoginEmail] = useState("owner@acme.test");
  const [tenantName, setTenantName] = useState("");
  const [statusMessage, setStatusMessage] = useState<string | undefined>();

  const selectedMembership = useMemo(
    () =>
      currentUser?.memberships.find((membership) => membership.tenantId === selectedTenantId) ??
      currentUser?.memberships[0],
    [currentUser?.memberships, selectedTenantId]
  );

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
          <a className="nav-item active" href="#overview">
            <Activity aria-hidden="true" />
            Overview
          </a>
          <a className="nav-item" href="#members">
            <UserRound aria-hidden="true" />
            Members
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

        <section className="content-grid">
          <article className="panel" id="overview">
            <div className="panel-heading">
              <h2>Current access</h2>
              <CheckCircle2 aria-hidden="true" />
            </div>
            <dl className="details">
              <div>
                <dt>User</dt>
                <dd>{currentUser.name}</dd>
              </div>
              <div>
                <dt>Email</dt>
                <dd>{currentUser.email}</dd>
              </div>
              <div>
                <dt>Role</dt>
                <dd>{formatRole(selectedMembership.role)}</dd>
              </div>
              <div>
                <dt>Tenant slug</dt>
                <dd>{selectedMembership.tenantSlug}</dd>
              </div>
            </dl>
          </article>

          <article className="panel" id="members">
            <div className="panel-heading">
              <h2>Membership controls</h2>
              <UserRound aria-hidden="true" />
            </div>
            <ul className="control-list">
              <li>Active membership required before tenant context is accepted.</li>
              <li>Foreign tenant selection returns `403` in the API foundation.</li>
              <li>MFA requirement is visible per tenant membership.</li>
            </ul>
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
                Create
              </button>
              {statusMessage ? <p className="status-message">{statusMessage}</p> : null}
            </form>
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
