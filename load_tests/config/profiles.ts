export interface LoadProfile {
  stages: Array<{ duration: string; target: number; label?: string }>;
  thresholds: Record<string, string[]>;
}

// ==========================================
// CONFIGURATION CONSTANTS (Self-Documenting)
// ==========================================

// 50 VUs making requests continuously against a 250ms delayed endpoint(mock hibp in the /tests) creates
// roughly 200 concurrent active operations per second. This is the exact target
// threshold to test if our Argon2 spawn_blocking threads starve our availability.
const TARGET_STRESS_VIRTUAL_USERS = 50;
const INITIAL_COOLDOWN_VIRTUAL_USERS = 0;

export const LOAD_PROFILES: Record<string, LoadProfile> = {
  STRESS: {
    // Enforce our three-nines availability SLO promise.
    // If even a single health check or signup drops due to thread starvation, the test fails.
    thresholds: {
      http_req_failed: ["rate<0.001"], // 99.9% success rate required (availability gate)
      http_req_duration: ["p(95)<500"], // 95% of responses must return in under 500ms
    },
    stages: [
      {
        duration: "10s",
        target: TARGET_STRESS_VIRTUAL_USERS,
        label: "Ramp-up: Scale virtual workers up to target pressure",
      },
      {
        duration: "30s",
        target: TARGET_STRESS_VIRTUAL_USERS,
        label:
          "Sustained Stress: Saturate CPU & connections to trap thread exhaustion",
      },
      {
        duration: "10s",
        target: INITIAL_COOLDOWN_VIRTUAL_USERS,
        label: "Ramp-down: Graceful cleanup of connection pipelines",
      },
    ],
  },
};
