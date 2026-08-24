# Load tests

[k6](https://k6.io) scenarios for the Q-Trust backend API.

| Script | Profile | Thresholds |
|---|---|---|
| `k6-smoke.js` | 10 VUs for 30s | p95 < 300 ms, errors < 1%, checks > 99% |
| `k6-stress.js` | ramp 10 → 30 → 60 → 100 VUs over 5 min (sustained 100 for last minute) | p95 < 800 ms, errors < 2%, checks > 98% |

## Run

```bash
# install k6 once: https://grafana.com/docs/k6/latest/set-up/install-k6/
BASE_URL=http://localhost:3001 k6 run ops/loadtest/k6-smoke.js
BASE_URL=http://localhost:3001 k6 run ops/loadtest/k6-stress.js
```

`BASE_URL` defaults to `http://localhost:3001`. Point it at staging, never at
production — the stress profile generates sustained read traffic.

## Reading results

* `http_req_duration` percentiles are per-endpoint tagged (`health`, `assets`,
  `org-assets`) — check the breakdown before blaming "the API".
* A failing threshold exits non-zero, so both scripts are CI-schedulable:
  `k6 run --quiet ops/loadtest/k6-smoke.js && echo ok`.
* The stress test's knee (where p95 crosses 800 ms or errors exceed 2%) is the
  practical capacity of your deployment; scale Postgres/RPC endpoints first,
  then API replicas.
