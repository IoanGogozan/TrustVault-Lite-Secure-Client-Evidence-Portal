import type { PrivateObjectStorage } from "@trustvault/storage";
import { randomUUID } from "node:crypto";
import type { AuditEvent } from "@trustvault/audit";
import { redactAuditMetadata } from "@trustvault/audit";
import type { AppStore, ScanJob } from "./domain.js";
import type { DocumentReadScope, DocumentRepository } from "./documents.js";

export type ScanJobQueue = {
  enqueue(input: {
    tenantId: string;
    documentId: string;
    versionId: string;
    storageKey: string;
    queuedBy: string;
  }): Promise<ScanJob>;
  processNext(tenantId?: string): Promise<ScanJob | undefined>;
};

export class InMemoryScanJobQueue implements ScanJobQueue {
  constructor(
    private readonly store: AppStore,
    private readonly documentRepository: DocumentRepository,
    private readonly storage: PrivateObjectStorage
  ) {}

  async enqueue(input: {
    tenantId: string;
    documentId: string;
    versionId: string;
    storageKey: string;
    queuedBy: string;
  }): Promise<ScanJob> {
    const now = new Date();
    const job = {
      id: `scan_job_${randomUUID()}`,
      tenantId: input.tenantId,
      documentId: input.documentId,
      versionId: input.versionId,
      storageKey: input.storageKey,
      status: "queued" as const,
      queuedBy: input.queuedBy,
      attempts: 0,
      createdAt: now,
      updatedAt: now
    };

    this.store.scanJobs.push(job);
    appendSystemAuditEvent(this.store, {
      tenantId: job.tenantId,
      action: "document.scan_queued",
      entityType: "document_version",
      entityId: job.versionId,
      result: "success",
      metadata: {
        documentId: job.documentId,
        scanJobId: job.id
      }
    });

    return job;
  }

  async processNext(tenantId?: string): Promise<ScanJob | undefined> {
    const job = this.store.scanJobs.find(
      (candidate) =>
        candidate.status === "queued" && (!tenantId || candidate.tenantId === tenantId)
    );

    if (!job) {
      return undefined;
    }

    job.status = "processing";
    job.attempts += 1;
    job.updatedAt = new Date();

    const content = await this.storage.get(job.storageKey);

    if (!content) {
      job.status = "failed";
      job.updatedAt = new Date();
      appendSystemAuditEvent(this.store, {
        tenantId: job.tenantId,
        action: "document.scan_failed",
        entityType: "document_version",
        entityId: job.versionId,
        result: "failure",
        metadata: {
          documentId: job.documentId,
          scanJobId: job.id,
          reason: "storage_object_missing"
        }
      });
      return job;
    }

    const scanStatus = scanFileContent(content);
    const scope: DocumentReadScope = {
      tenantId: job.tenantId,
      role: "owner"
    };
    await this.documentRepository.updateScanStatus(scope, job.versionId, scanStatus);

    job.status = "completed";
    job.updatedAt = new Date();
    appendSystemAuditEvent(this.store, {
      tenantId: job.tenantId,
      action: scanStatus === "clean" ? "document.scan_clean" : "document.scan_blocked",
      entityType: "document_version",
      entityId: job.versionId,
      result: scanStatus === "clean" ? "success" : "failure",
      metadata: {
        documentId: job.documentId,
        scanJobId: job.id,
        scanStatus
      }
    });

    return job;
  }
}

export function scanFileContent(content: Buffer): "clean" | "blocked" {
  const marker = content.toString("utf8").toLowerCase();

  return marker.includes("eicar") || marker.includes("malware-demo") ? "blocked" : "clean";
}

function appendSystemAuditEvent(
  store: AppStore,
  input: Omit<AuditEvent, "id" | "actorType" | "ipHash" | "userAgent" | "metadata" | "createdAt"> & {
    metadata: Record<string, unknown>;
  }
): void {
  store.auditEvents.push({
    id: `audit_${randomUUID()}`,
    tenantId: input.tenantId,
    actorType: "system",
    action: input.action,
    entityType: input.entityType,
    ...(input.entityId ? { entityId: input.entityId } : {}),
    result: input.result,
    ipHash: "system",
    userAgent: "scan-worker",
    metadata: redactAuditMetadata(input.metadata),
    createdAt: new Date()
  });
}
