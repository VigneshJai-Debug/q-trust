// Q-Trust smoke load test — sanity check that the API holds up under light
// concurrent read traffic. Run: BASE_URL=http://localhost:3001 k6 run ops/loadtest/k6-smoke.js
import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://localhost:3001";

export const options = {
  vus: 10,
  duration: "30s",
  thresholds: {
    http_req_duration: ["p(95)<300"],
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
};

export default function () {
  const res = http.get(`${BASE_URL}/health`, { tags: { name: "health" } });
  check(res, {
    "health is 200": (r) => r.status === 200,
    "status ok": (r) => r.json("status") === "ok",
  });

  http.get(`${BASE_URL}/v1/assets/0x${"0".repeat(64)}`, { tags: { name: "assets" } });
  // Unknown asset → 404 is the expected fast path; both 200/404 pass latency.

  sleep(1);
}
