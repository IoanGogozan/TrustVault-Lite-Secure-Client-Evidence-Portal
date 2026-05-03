export type AppEnvironment = "development" | "test" | "production";

export type BaseConfig = {
  env: AppEnvironment;
  appName: string;
};

export function readBaseConfig(env: NodeJS.ProcessEnv = process.env): BaseConfig {
  const appEnv = env.NODE_ENV ?? "development";

  if (!isAppEnvironment(appEnv)) {
    throw new Error(`Invalid NODE_ENV: ${appEnv}`);
  }

  return {
    env: appEnv,
    appName: env.APP_NAME ?? "TrustVault Lite"
  };
}

function isAppEnvironment(value: string): value is AppEnvironment {
  return value === "development" || value === "test" || value === "production";
}

