// load_tests/modules/payload.ts

export interface SignupPayload {
  name: string;
  password: string;
}

/**
 * Generates a unique, deterministic registration payload
 * using k6's execution identifiers.
 */
export function generateSignupPayload(vu: number, iter: number): SignupPayload {
  return {
    name: `ts-user-${vu}-${iter}-${crypto.randomUUID().slice(0, 8)}`,
    password: "Super-Secure-Password-123!",
  };
}
