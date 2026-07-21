import http from "k6/http";
import { ENV } from "../../config/environment";
import type { UpdateUserPayload } from "../payload";

export function updateUser(payload: UpdateUserPayload, cookie?: string) {
  const url = `${ENV.baseUrl}/users`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (cookie) {
    headers["Cookie"] = cookie;
  }

  return http.put(url, JSON.stringify(payload), {
    headers,
    timeout: `${ENV.timeoutMs}ms`,
  });
}
