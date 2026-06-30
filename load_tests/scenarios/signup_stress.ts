import { check, fail, sleep } from "k6";
import http from "k6/http";

import { ENV } from "../config/environment";
import { LOAD_PROFILES } from "../config/profiles";
import { signup } from "../modules/endpoints/auth";
import { checkSystemHealth } from "../modules/endpoints/health";
import { generateSignupPayload } from "../modules/payload";

export const options = LOAD_PROFILES.STRESS;
const BASE_URL = ENV.baseUrl;

/**
 * Pre-flight setup phase: Runs exactly ONCE before VUs start.
 * If this fails, the entire load test aborts immediately.
 */
export function setup() {
  console.log(`[Pre-flight] Pinging health check at: ${BASE_URL}/health_check`);

  const res = http.get(`${BASE_URL}/health_check`, {
    timeout: "3s", // Short timeout: if it's not up in 3s, fail immediately
  });

  const isUp = check(res, {
    "API is alive and reachable": (r) => r.status === 200,
  });

  if (!isUp) {
    // This forcibly blows up the k6 run right here
    fail(
      "[CRITICAL] Pre-flight health check failed! Aborting load test execution.",
    );
  }

  console.log("[Pre-flight] API is responsive. Starting load test stages...");
}

export default function () {
  // 1. Arrange: Generate a unique, type-safe payload
  const userPayload = generateSignupPayload(__VU, __ITER);

  // 2. Act: Trigger both actions sequentially within this iteration loop
  const signupResponse = signup(userPayload);
  // Hit the lightweight health_check endpoint simultaneously
  // If it regresses we know that indeed availability is affected by underlying
  // calls to HIBP and argon2 hashing cost on the signup handler then decide whether to optimize
  const healthResponse = checkSystemHealth();

  // 3. Assert: Validate that BOTH routes processed successfully
  check(signupResponse, {
    "Signup response was 201": (r) => r.status === 201,
  });

  check(healthResponse, {
    "System Health check returned 200": (r) => r.status === 200,
  });

  // Small delay to prevent infinite immediate loops crashing the local runtime engine
  sleep(0.1);
}
