import http from "k6/http";
import { check, sleep } from "k6";
import { Trend, Rate, Counter } from "k6/metrics";

const APP_URL = __ENV.APP_URL || "http://localhost:80";

export const options = {
  stages: [
    { duration: "30s", target: 10 },  // montée progressive
    { duration: "1m",  target: 50 },  // charge normale
    { duration: "30s", target: 100 }, // pic de charge
    { duration: "30s", target: 0 },   // descente
  ],
  thresholds: {
    http_req_duration: ["p(95)<2000"], // 95% des requêtes < 2s
    http_req_failed:   ["rate<0.1"],   // moins de 10% d'erreurs
  },
};

export default function () {
  const res = http.get(APP_URL);

  check(res, {
    "status is 200": (r) => r.status === 200,
    "response time < 2s": (r) => r.timings.duration < 2000,
  });

  sleep(1);
}

export function handleSummary(data) {
  const metrics = data.metrics;

  const summary = {
    product_name:     __ENV.PRODUCT_NAME || "unknown",
    app_url:          APP_URL,
    duration_secs:    120,
    vus:              100,
    total_requests:   metrics.http_reqs?.values?.count || 0,
    failed_requests:  metrics.http_req_failed?.values?.passes || 0,
    error_rate:       (metrics.http_req_failed?.values?.rate || 0) * 100,
    avg_response_ms:  metrics.http_req_duration?.values?.avg || 0,
    min_response_ms:  metrics.http_req_duration?.values?.min || 0,
    max_response_ms:  metrics.http_req_duration?.values?.max || 0,
    p90_response_ms:  metrics.http_req_duration?.values["p(90)"] || 0,
    p95_response_ms:  metrics.http_req_duration?.values["p(95)"] || 0,
    throughput:       metrics.http_reqs?.values?.rate || 0,
  };

  return {
    stdout: JSON.stringify(summary, null, 2),
    "summary.json": JSON.stringify(summary),
  };
}
