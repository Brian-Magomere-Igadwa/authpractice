// load_tests/modules/payload.ts

export interface SignupPayload {
  name: string;
  password: string;
}

export interface LoginPayload {
  name: string;
  password: string;
}

export interface UpdateUserPayload {
  name?: string;
  password?: string;
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

/**
 * Generates a structured login payload matching the
 * domain complexity and naming format of the application.
 */
export function generateLoginPayload(vu: number, iter: number): LoginPayload {
  return {
    name: `ts-user-${vu}-${iter}`,
    password: "Super-Secure-Password-123!",
  };
}

/**
 * Generates structured profile update payloads.
 */
export function generateUpdateUserPayload(
  vu: number,
  iter: number,
): UpdateUserPayload {
  return {
    name: `updated-name-${vu}-${iter}`,
    password: `Updated-Password-${vu}-${iter}!`,
  };
}
