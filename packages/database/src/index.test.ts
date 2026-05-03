import { describe, expect, it } from "vitest";
import { setTenantContext, withTenantContext, type SqlExecutor } from "./index.js";

class RecordingExecutor implements SqlExecutor {
  public readonly calls: Array<{ sql: string; parameters?: readonly unknown[] }> = [];

  async execute(sql: string, parameters?: readonly unknown[]): Promise<unknown> {
    this.calls.push(parameters ? { sql, parameters } : { sql });
    return undefined;
  }
}

describe("setTenantContext", () => {
  it("sets app.current_tenant_id with a parameterized query", async () => {
    const executor = new RecordingExecutor();
    const tenantId = "11111111-1111-4111-8111-111111111111";

    await setTenantContext(executor, tenantId);

    expect(executor.calls).toEqual([
      {
        sql: "SELECT set_config('app.current_tenant_id', $1, true)",
        parameters: [tenantId]
      }
    ]);
  });

  it("rejects invalid tenant ids before executing SQL", async () => {
    const executor = new RecordingExecutor();

    await expect(setTenantContext(executor, "not-a-uuid")).rejects.toThrow(
      "tenantId must be a valid UUID"
    );
    expect(executor.calls).toEqual([]);
  });
});

describe("withTenantContext", () => {
  it("sets tenant context before running tenant-scoped work in the transaction", async () => {
    const transaction = new RecordingExecutor();
    const runner = {
      async transaction<TResult>(
        callback: (transactionExecutor: RecordingExecutor) => Promise<TResult>
      ): Promise<TResult> {
        return callback(transaction);
      }
    };

    const result = await withTenantContext(
      runner,
      "22222222-2222-4222-8222-222222222222",
      async (tx) => {
        await tx.execute("SELECT * FROM documents WHERE id = $1", [
          "33333333-3333-4333-8333-333333333333"
        ]);

        return "ok";
      }
    );

    expect(result).toBe("ok");
    expect(transaction.calls).toEqual([
      {
        sql: "SELECT set_config('app.current_tenant_id', $1, true)",
        parameters: ["22222222-2222-4222-8222-222222222222"]
      },
      {
        sql: "SELECT * FROM documents WHERE id = $1",
        parameters: ["33333333-3333-4333-8333-333333333333"]
      }
    ]);
  });
});
