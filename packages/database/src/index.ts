export type SqlExecutor = {
  execute(sql: string, parameters?: readonly unknown[]): Promise<unknown>;
};

export type TransactionRunner<TTransaction extends SqlExecutor> = {
  transaction<TResult>(callback: (transaction: TTransaction) => Promise<TResult>): Promise<TResult>;
};

export async function setTenantContext(
  executor: SqlExecutor,
  tenantId: string
): Promise<void> {
  assertUuid(tenantId);

  await executor.execute("SELECT set_config('app.current_tenant_id', $1, true)", [tenantId]);
}

export async function withTenantContext<TTransaction extends SqlExecutor, TResult>(
  runner: TransactionRunner<TTransaction>,
  tenantId: string,
  callback: (transaction: TTransaction) => Promise<TResult>
): Promise<TResult> {
  return runner.transaction(async (transaction) => {
    await setTenantContext(transaction, tenantId);

    return callback(transaction);
  });
}

function assertUuid(value: string): void {
  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  if (!uuidPattern.test(value)) {
    throw new Error("tenantId must be a valid UUID");
  }
}

