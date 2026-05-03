import { randomUUID } from "node:crypto";

export type StoredObjectMetadata = {
  storageKey: string;
  sizeBytes: number;
  contentType: string;
};

export type PrivateObjectStorage = {
  put(input: {
    tenantId: string;
    documentId: string;
    contentType: string;
    content: Buffer;
  }): Promise<StoredObjectMetadata>;
  get(storageKey: string): Promise<Buffer | undefined>;
  createSignedDownload(input: {
    storageKey: string;
    expiresInSeconds: number;
  }): Promise<{ storageKey: string; expiresAt: Date }>;
};

export type S3CompatibleClient = {
  putObject(input: {
    bucket: string;
    key: string;
    body: Buffer;
    contentType: string;
  }): Promise<void>;
  getObject(input: {
    bucket: string;
    key: string;
  }): Promise<Buffer | undefined>;
  createPresignedGetUrl(input: {
    bucket: string;
    key: string;
    expiresInSeconds: number;
  }): Promise<string>;
};

export class InMemoryPrivateObjectStorage implements PrivateObjectStorage {
  constructor(private readonly objects: Record<string, string> = {}) {}

  async put(input: {
    tenantId: string;
    documentId: string;
    contentType: string;
    content: Buffer;
  }): Promise<StoredObjectMetadata> {
    const storageKey = createDocumentStorageKey(input.tenantId, input.documentId);
    this.objects[storageKey] = input.content.toString("base64");

    return {
      storageKey,
      sizeBytes: input.content.byteLength,
      contentType: input.contentType
    };
  }

  async get(storageKey: string): Promise<Buffer | undefined> {
    const value = this.objects[storageKey];

    return value ? Buffer.from(value, "base64") : undefined;
  }

  async createSignedDownload(input: {
    storageKey: string;
    expiresInSeconds: number;
  }): Promise<{ storageKey: string; expiresAt: Date }> {
    return {
      storageKey: input.storageKey,
      expiresAt: new Date(Date.now() + input.expiresInSeconds * 1000)
    };
  }
}

export class S3CompatiblePrivateObjectStorage implements PrivateObjectStorage {
  constructor(
    private readonly client: S3CompatibleClient,
    private readonly bucket: string
  ) {}

  async put(input: {
    tenantId: string;
    documentId: string;
    contentType: string;
    content: Buffer;
  }): Promise<StoredObjectMetadata> {
    const storageKey = createDocumentStorageKey(input.tenantId, input.documentId);
    await this.client.putObject({
      bucket: this.bucket,
      key: storageKey,
      body: input.content,
      contentType: input.contentType
    });

    return {
      storageKey,
      sizeBytes: input.content.byteLength,
      contentType: input.contentType
    };
  }

  async get(storageKey: string): Promise<Buffer | undefined> {
    return this.client.getObject({
      bucket: this.bucket,
      key: storageKey
    });
  }

  async createSignedDownload(input: {
    storageKey: string;
    expiresInSeconds: number;
  }): Promise<{ storageKey: string; expiresAt: Date }> {
    await this.client.createPresignedGetUrl({
      bucket: this.bucket,
      key: input.storageKey,
      expiresInSeconds: input.expiresInSeconds
    });

    return {
      storageKey: input.storageKey,
      expiresAt: new Date(Date.now() + input.expiresInSeconds * 1000)
    };
  }
}

export function createDocumentStorageKey(tenantId: string, documentId: string): string {
  return `${tenantId}/documents/${documentId}/${randomUUID()}`;
}
