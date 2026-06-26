import http from "k6/http";
import { ENV } from "../../config/environment";
import type { SignupPayload } from "../payload";

export function signup(payload: SignupPayload) {
  const url = `${ENV.baseUrl}/users`;
  const headers = { "Content-Type": "application/json" };

  return http.post(url, JSON.stringify(payload), {
    headers,
    timeout: `${ENV.timeoutMs}ms`, // Dynamically enforce your environment timeouts
  });
}
