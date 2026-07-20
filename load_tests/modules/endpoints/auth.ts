import http from "k6/http";
import { ENV } from "../../config/environment";
import type { LoginPayload, SignupPayload } from "../payload";

export function signup(payload: SignupPayload) {
  const url = `${ENV.baseUrl}/users`;
  const headers = { "Content-Type": "application/json" };

  return http.post(url, JSON.stringify(payload), {
    headers,
    timeout: `${ENV.timeoutMs}ms`, // Dynamically enforce your environment timeouts
  });
}

export function login(payload: LoginPayload) {
  const url = `${ENV.baseUrl}/auth`;
  const headers = { "Content-Type": "application/json" };

  return http.post(url, JSON.stringify(payload), {
    headers,
    timeout: `${ENV.timeoutMs}ms`, // Dynamically enforce your environment timeouts
  });
}
