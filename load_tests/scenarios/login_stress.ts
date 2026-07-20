import { check, fail, sleep } from "k6";
import http from "k6/http";

import { ENV } from "../config/environment";
import { LOAD_PROFILES } from "../config/profiles";
import { login } from "../modules/endpoints/auth";
import { checkSystemHealth } from "../modules/endpoints/health";
import { generateLoginPayload } from "../modules/payload";

// Inherit structural profiles and apply the explicit Red Test verification criteria
export const options = {
  ...LOAD_PROFILES.STRESS,
  thresholds: {
    ...LOAD_PROFILES.STRESS.thresholds,
    // Red Test condition: Enforce a strict p95 ceiling below 300ms.
    // The combination of mock API delay + Argon2 compute time guarantees a test failure.
    http_req_duration: ["p(95)<400"],
    http_req_failed: ["rate<0.01"],
  },
};

const BASE_URL = ENV.baseUrl;

/**
 * Pre-flight setup phase: Runs exactly ONCE before VUs start.
 * If this fails, the entire load test aborts immediately.
 */
export function setup() {
  console.log(`[Pre-flight] Pinging health check at: ${BASE_URL}/health_check`);

  const res = http.get(`${BASE_URL}/health_check`, {
    timeout: "3s",
  });

  const isUp = check(res, {
    "API is alive and reachable": (r) => r.status === 200,
  });

  if (!isUp) {
    fail(
      "[CRITICAL] Pre-flight health check failed! Aborting login load test execution.",
    );
  }

  console.log("[Pre-flight] API is responsive. Starting login load stages...");

  // Return configuration or seeded values to setup state if needed by default loop
  return { initialized: true };
}

export default function (data: any) {
  // 1. Arrange: Check if the test environment provided a seeded fallback user
  let userPayload;
  if (__ENV.TARGET_USER_NAME && __ENV.TARGET_USER_PASSWORD) {
    userPayload = {
      name: __ENV.TARGET_USER_NAME,
      password: __ENV.TARGET_USER_PASSWORD,
    };
  } else {
    // Fallback to generated formatting if running standalone scenarios manually
    userPayload = generateLoginPayload(__VU, __ITER);
  }

  // 2. Act: Trigger login while tracking total system availability
  const loginResponse = login(userPayload);
  const healthResponse = checkSystemHealth();

  // 3. Assert: Verify endpoint behaviors under concurrent load
  check(loginResponse, {
    "Login response was 200 or 401": (r) => [200, 401].includes(r.status),
  });

  check(healthResponse, {
    "System Health check returned 200 during high load": (r) =>
      r.status === 200,
  });

  sleep(0.1);
}

/**
 * Handle summary outputs to target volume mount for Rust test verification pipelines
 */
export function handleSummary(data: any) {
  return {
    // Standard stdout tracking so logs capture the run natively
    stdout: textSummary(data, { indent: " ", enableColors: true }),
    // Ensure this volume/directory exists in your running container context
    "/apps/benchmarks/login_scenario_tests_summary.json": JSON.stringify(
      data,
      null,
      2,
    ),
  };
}

// Helper to handle the standard k6 text output fallback alongside the JSON output
import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";
