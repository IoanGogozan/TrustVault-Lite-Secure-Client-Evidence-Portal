import { describe, expect, it } from "vitest";
import {
  InMemoryPrivateObjectStorage,
  S3CompatiblePrivateObjectStorage,
  type S3CompatibleClient
} from "./index.js";

describe("InMemoryPrivateObjectStorage", () => {
  it("stores private objects under generated tenant document keys", async () => {
    const storage = new InMemoryPrivateObjectStorage();

    const object = await storage.put({
      tenantId: "tenant_a",
      documentId: "document_1",
      contentType: "application/pdf",
      content: Buffer.from("%PDF-")
    });

    expect(object.storageKey).toMatch(/^tenant_a\/documents\/document_1\//);
    await expect(storage.get(object.storageKey)).resolves.toEqual(Buffer.from("%PDF-"));
  });
});

describe("S3CompatiblePrivateObjectStorage", () => {
  it("delegates object storage and presigning to the provided client", async () => {
    const calls: string[] = [];
    const client: S3CompatibleClient = {
      async putObject(input) {
        calls.push(`put:${input.bucket}:${input.key}:${input.contentType}`);
      },
      async getObject(input) {
        calls.push(`get:${input.bucket}:${input.key}`);
        return Buffer.from("%PDF-");
      },
      async createPresignedGetUrl(input) {
        calls.push(`sign:${input.bucket}:${input.key}:${input.expiresInSeconds}`);
        return "https://storage.example/signed";
      }
    };
    const storage = new S3CompatiblePrivateObjectStorage(client, "trustvault-documents");

    const object = await storage.put({
      tenantId: "tenant_a",
      documentId: "document_1",
      contentType: "application/pdf",
      content: Buffer.from("%PDF-")
    });
    await expect(storage.get(object.storageKey)).resolves.toEqual(Buffer.from("%PDF-"));
    await storage.createSignedDownload({
      storageKey: object.storageKey,
      expiresInSeconds: 300
    });

    expect(calls).toEqual([
      expect.stringMatching(/^put:trustvault-documents:tenant_a\/documents\/document_1\/.+:application\/pdf$/),
      expect.stringMatching(/^get:trustvault-documents:tenant_a\/documents\/document_1\/.+$/),
      expect.stringMatching(/^sign:trustvault-documents:tenant_a\/documents\/document_1\/.+:300$/)
    ]);
  });
});
