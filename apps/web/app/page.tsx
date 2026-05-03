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
import { useMemo, useState } from "react";

type Role = "Owner" | "Admin" | "Member" | "Viewer" | "Auditor";

type DemoMembership = {
  tenantId: string;
  tenantName: string;
  tenantSlug: string;
  role: Role;
  mfaRequired: boolean;
};

const demoMemberships: [DemoMembership, ...DemoMembership[]] = [
  {
    tenantId: "tenant_acme",
    tenantName: "Acme Corp",
    tenantSlug: "acme",
    role: "Owner",
    mfaRequired: true
  },
  {
    tenantId: "tenant_globex",
    tenantName: "Globex Review",
    tenantSlug: "globex-review",
    role: "Auditor",
    mfaRequired: true
  }
];

const demoUser = {
  name: "Acme Owner",
  email: "owner@acme.test",
  memberships: demoMemberships
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

export default function Home() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [selectedTenantId, setSelectedTenantId] = useState(demoUser.memberships[0].tenantId);

  const selectedMembership = useMemo(
    () =>
      demoUser.memberships.find((membership) => membership.tenantId === selectedTenantId) ??
      demoUser.memberships[0],
    [selectedTenantId]
  );

  if (!isLoggedIn) {
    return (
      <main className="login-shell">
        <section className="login-panel" aria-label="Demo login">
          <div className="brand-mark">
            <ShieldCheck aria-hidden="true" />
          </div>
          <div>
            <h1>TrustVault Lite</h1>
            <p>Secure client evidence portal</p>
          </div>
          <button className="primary-action" type="button" onClick={() => setIsLoggedIn(true)}>
            <KeyRound aria-hidden="true" />
            Demo login
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
          <a className="nav-item" href="#keys">
            <KeyRound aria-hidden="true" />
            API Keys
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
                value={selectedTenantId}
                onChange={(event) => setSelectedTenantId(event.target.value)}
              >
                {demoUser.memberships.map((membership) => (
                  <option key={membership.tenantId} value={membership.tenantId}>
                    {membership.tenantName}
                  </option>
                ))}
              </select>
            </label>
            <button className="icon-action" type="button" onClick={() => setIsLoggedIn(false)}>
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
                <dd>{demoUser.name}</dd>
              </div>
              <div>
                <dt>Email</dt>
                <dd>{demoUser.email}</dd>
              </div>
              <div>
                <dt>Role</dt>
                <dd>{selectedMembership.role}</dd>
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
        </section>
      </section>
    </main>
  );
}
