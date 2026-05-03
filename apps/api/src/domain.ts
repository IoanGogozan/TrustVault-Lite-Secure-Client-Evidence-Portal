export type UserStatus = "active" | "disabled";
export type MembershipRole = "owner" | "admin" | "member" | "viewer" | "auditor";
export type MembershipStatus = "active" | "invited" | "suspended";

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
  createdAt: Date;
};

export type Session = {
  id: string;
  userId: string;
  createdAt: Date;
  revokedAt?: Date;
};

export type AppStore = {
  users: User[];
  tenants: Tenant[];
  memberships: Membership[];
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
        createdAt: now
      }
    ],
    sessions: []
  };
}

