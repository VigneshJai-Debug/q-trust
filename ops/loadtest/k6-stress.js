// Q-Trust stress test — ramps 10 → 100 VUs over 5 minutes to find the knee of
// the curve and validate p95/latency + error budgets under sustained load.
// Run: BASE_URL=http://localhost:3001 k6 run ops/loadtest/k6-stress.js
import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://localhost:3001";

export const options = {
  stages: [
    { duration: "1m", target: 10 },
    { duration: "1m", target: 30 },
    { duration: "1m", target: 60 },
    { duration: "1m", target: 100 },
    { duration: "1m", target: 100 },
  ],
  // Thresholds are scoped per request tag: the `assets` probe intentionally
  // targets a nonexistent asset (404 fast path), so a global
  // http_req_failed threshold would fail by construction.
  thresholds: {
    "http_req_duration": ["p(95)<800"],
    "http_req_duration{name:health}": ["p(95)<100"],
    "http_req_failed{name:health}": ["rate<0.02"],
    "http_req_failed{name:org-assets}": ["rate<0.02"],
    checks: ["rate>0.98"],
  },
};

export default function () {
  const res = http.get(`${BASE_URL}/health`, { tags: { name: "health" } });
  check(res, {
    "health is 200": (r) => r.status === 200,
    "status ok": (r) => r.json("status") === "ok",
  });

  // Mixed read workload: unknown asset (404 fast path) + org query params.
  http.get(`${BASE_URL}/v1/assets/0x${"0".repeat(64)}`, {
    tags: { name: "assets" },
  });
  http.get(
    `${BASE_URL}/v1/orgs/0x${"0".repeat(40)}/assets?offset=0&limit=10`,
    { tags: { name: "org-assets" } },
  );

  sleep(Math.random() * 2);
}
