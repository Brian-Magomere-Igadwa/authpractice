// load_tests/modules/endpoints/health.ts
import http from "k6/http";
import { ENV } from "../../config/environment";

/**
 * Fires a fast GET request against the server's health check route
 * to guarantee it responds even when the registration system is melting.
 */
export function checkSystemHealth() {
  const url = `${ENV.baseUrl}/health_check`;

  const params = {
    tags: { name: "HealthCheck" }, // Labeling this makes it searchable in your k6 stdout histogram logs
  };

  const response = http.get(url, params);
  return response;
}
