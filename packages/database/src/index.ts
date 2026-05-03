import pg from "pg";

const { Pool } = pg;

export type SqlExecutor = {
  execute<TResult extends pg.QueryResultRow = pg.QueryResultRow>(
    sql: string,
    parameters?: readonly unknown[]
  ): Promise<QueryResult<TResult>>;
};

export type TransactionRunner<TTransaction extends SqlExecutor> = {
  transaction<TResult>(callback: (transaction: TTransaction) => Promise<TResult>): Promise<TResult>;
};

export type QueryResult<TResult> = {
  rows: TResult[];
  rowCount: number;
};

export type DatabasePoolOptions = {
  connectionString: string;
};

export class DatabasePool implements TransactionRunner<DatabaseTransaction> {
  private readonly pool: pg.Pool;

  constructor(options: DatabasePoolOptions) {
    this.pool = new Pool({
      connectionString: options.connectionString
    });
  }

  async transaction<TResult>(
    callback: (transaction: DatabaseTransaction) => Promise<TResult>
  ): Promise<TResult> {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const result = await callback(new DatabaseTransaction(client));
      await client.query("COMMIT");

      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

export class DatabaseTransaction implements SqlExecutor {
  constructor(private readonly client: pg.PoolClient) {}

  async execute<TResult extends pg.QueryResultRow = pg.QueryResultRow>(
    sql: string,
    parameters?: readonly unknown[]
  ): Promise<QueryResult<TResult>> {
    const result = await this.client.query<TResult>(sql, parameters ? [...parameters] : undefined);

    return {
      rows: result.rows,
      rowCount: result.rowCount ?? 0
    };
  }
}

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
