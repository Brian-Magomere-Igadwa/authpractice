export interface EnvironmentConfig {
  baseUrl: string;
  timeoutMs: number;
}

const DEV_MACHINE_LOCALHOST = "http://127.0.0.1:8000";
const PROD_MACHINE_BASE_URL = "http://127.0.0.1:8000";

// ==========================================
// ENVIRONMENT SETUP
// ==========================================

// If running inside the automated Cargo test suite, read the injected Docker host routing address.
// Otherwise, fall back to your native local development port.
// Dynamically read what Rust passed us, or fall back to 8000 for manual local CLI runs
const dynamicBaseUrl = __ENV.K6_ENV_BASE_URL || DEV_MACHINE_LOCALHOST;

const local: EnvironmentConfig = {
  baseUrl: dynamicBaseUrl,
  timeoutMs: 5000,
};

const production: EnvironmentConfig = {
  // todo(change to prod url later)
  baseUrl: __ENV.PROD_API_URL || PROD_MACHINE_BASE_URL,
  timeoutMs: 2000,
};

const currentEnv = __ENV.ENV === "production" ? production : local;

export { currentEnv as ENV };
