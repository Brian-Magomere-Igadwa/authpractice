import { check, fail, sleep } from "k6";
import http from "k6/http";
import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";

import { ENV } from "../config/environment";
import { LOAD_PROFILES } from "../config/profiles";
import { login } from "../modules/endpoints/auth";
import { checkSystemHealth } from "../modules/endpoints/health";
import { updateUser } from "../modules/endpoints/user";
import { generateUpdateUserPayload } from "../modules/payload";

export const options = {
  ...LOAD_PROFILES.STRESS,
  thresholds: {
    ...LOAD_PROFILES.STRESS.thresholds,
    http_req_duration: ["p(95)<2000"],
    http_req_failed: ["rate<0.01"],
  },
};

const BASE_URL = ENV.baseUrl;

interface SetupData {
  cookie?: string;
}

export function setup(): SetupData {
  console.log(`[Pre-flight] Pinging health check at: ${BASE_URL}/health_check`);

  const res = http.get(`${BASE_URL}/health_check`, { timeout: "3s" });
  const isUp = check(res, {
    "API is alive and reachable": (r) => r.status === 200,
  });

  if (!isUp) {
    fail(
      "[CRITICAL] Pre-flight health check failed! Aborting update profile load test.",
    );
  }

  console.log(
    "[Pre-flight] API reachable. Attempting initial authentication...",
  );

  let cookieHeader: string | undefined;

  if (__ENV.TARGET_USER_NAME && __ENV.TARGET_USER_PASSWORD) {
    const loginRes = login({
      name: __ENV.TARGET_USER_NAME,
      password: __ENV.TARGET_USER_PASSWORD,
    });

    const isLoginOk = check(loginRes, {
      "Setup login successful": (r) => r.status === 200,
    });

    if (!isLoginOk) {
      fail(
        `[CRITICAL] Setup login failed with status ${loginRes.status}: ${loginRes.body}`,
      );
    }

    // CRITICAL: Extract ONLY key=value (e.g. "session_id=123"), stripping "; Path=/; HttpOnly"
    const setCookie = loginRes.headers["Set-Cookie"];
    if (typeof setCookie === "string") {
      cookieHeader = setCookie.split(";")[0];
    }
  }

  return { cookie: cookieHeader };
}

export default function (data: SetupData) {
  // Generate payload for PUT /user
  const updatePayload = generateUpdateUserPayload(__VU, __ITER);

  // Send request with sanitized session cookie
  const updateResponse = updateUser(updatePayload, data.cookie);
  const healthResponse = checkSystemHealth();

  // Temporary debug print on VU 1 iteration 0 if it fails
  if (__ITER === 0 && __VU === 1 && updateResponse.status !== 200) {
    console.log(
      `[DEBUG VU 1] PUT /user returned HTTP ${updateResponse.status}`,
    );
    console.log(`[DEBUG VU 1] Cookie sent: ${data.cookie}`);
    console.log(`[DEBUG VU 1] Body: ${updateResponse.body}`);
  }

  check(updateResponse, {
    "Update profile response was 200": (r) => r.status === 200,
  });

  check(healthResponse, {
    "System Health check returned 200 during profile updates": (r) =>
      r.status === 200,
  });

  sleep(0.1);
}

export function handleSummary(data: any) {
  return {
    stdout: textSummary(data, { indent: " ", enableColors: true }),
    "/apps/benchmarks/update_profile_scenario_tests_summary.json":
      JSON.stringify(data, null, 2),
  };
}
