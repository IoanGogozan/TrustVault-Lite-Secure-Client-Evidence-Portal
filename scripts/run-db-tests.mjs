import { spawnSync } from "node:child_process";

const result = spawnSync("pnpm", ["--filter", "@trustvault/api", "test"], {
  stdio: "inherit",
  shell: process.platform === "win32",
  env: {
    ...process.env,
    RUN_DB_TESTS: "1",
    DATABASE_URL:
      process.env.DATABASE_URL ??
      "postgres://trustvault_app:trustvault_app_dev_password@localhost:55432/trustvault"
  }
});

process.exit(result.status ?? 1);
