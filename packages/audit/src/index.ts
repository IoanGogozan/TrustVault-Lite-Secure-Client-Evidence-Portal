export type AuditActorType = "user" | "api_key" | "system" | "support";
export type AuditResult = "success" | "failure";

export type AuditEvent = {
  id: string;
  tenantId: string;
  actorUserId?: string;
  actorType: AuditActorType;
  action: string;
  entityType: string;
  entityId?: string;
  result: AuditResult;
  ipHash: string;
  userAgent: string;
  metadata: Record<string, unknown>;
  createdAt: Date;
};

const secretKeyPatterns = [/password/i, /token/i, /secret/i, /api[-_]?key/i];

export function redactAuditMetadata(
  metadata: Record<string, unknown>
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(metadata).map(([key, value]) => [
      key,
      secretKeyPatterns.some((pattern) => pattern.test(key)) ? "[REDACTED]" : value
    ])
  );
}

