# Q-Trust — Specialist Sub-Agent Audit (29 Aug 2026)

> Nine specialist reviews of the live repository, each with **verified**
> findings (code-checked) and prioritized actions. Claims not verified in
> code are marked **inference**. Companion visuals: [`docs/design/`](design/).

**Headline:** the engineering is ahead of the market's *awareness*. The gap
is no longer code quality — it is (1) independent verification, (2) public
deployment, and (3) making the evidence story visible to buyers. Each
specialist below confirms the first two and specifies the third.

---

## Sub-agent 1 · Smart Contracts Specialist

**Verdict: 78/100 — strong patterns, governance + audit gap.**

### Verified strengths
- 11 UUPS registries: `AccessControl` + `ReentrancyGuard` + `Pausable` +
  `Initializable`, EIP-712 with chain/contract/nonce binding, nonce replay
  protection, implementation initializers disabled, relayer path checks the
  recovered signer has `REGISTRAR_ROLE` (not just a valid signature).
- 207 Foundry tests incl. invariant (1000 runs), fuzz, attack tests; Halmos
  symbolic execution in CI.

### Lagging (priority order)
1. **No external audit.** Nothing substitutes for it. Engage OZ / Trail of
   Bits / Code4rena; commit the report to `docs/audits/`.
2. **11 independent upgrade surfaces.** Group into 3 clusters
   (Core / Trust-Governance / Compliance) to shrink permissions × storage ×
   upgrade surfaces. Keep logical separation; reduce deployment coupling.
3. **Governance still deployer-EOA.** Deploy `Safe 2/3 → TimelockController
   (7d)` and transfer `DEFAULT_ADMIN_ROLE`. Emergency pause must exist but
   must *not* be able to upgrade.
4. **Storage-layout validation not in CI.** Add OpenZeppelin Upgrades
   checks + solc storage layout diff on every PR touching contracts.

### Actions (this week → next month)
```
1. Pause + freeze: no new features; audit prep
2. Multisig + timelock deployment (staging → Sepolia)
3. Storage-layout CI gate
4. Fork tests against Sepolia/Mainnet state
```

---

## Sub-agent 2 · Backend / Indexer Specialist

**Verdict: 82/100 — genuinely production-lean; two operational gaps.**

### Verified strengths
- Fastify 5: rate limits on every relay POST, Helmet, CORS, OpenAPI,
  Sentry, pino, Prometheus metrics, constant-time API-key compare.
- **Indexer already has reorg handling** (`recordProcessedBlock` +
  hash-mismatch rewind) — the "reorg risk" from earlier reviews is
  addressed in code.
- **Real Ed25519 VC issue/verify** (byte-compatible with the Python SDK,
  proven both directions), `did:web` fetch with SSRF guards.
- Read model / chain split is clean; graceful RPC fallback.

### Lagging
1. **No reorg/failure tests in CI.** The reorg code exists; prove it with
   a test that simulates a forked chain and asserts rewinding.
2. **Single RPC provider in places.** `rpc-pool.ts` exists — wire ≥2
   independent Base providers with automatic failover + health checks.
3. **Operational audit log** (who scanned/attested what) is not yet
   append-only/tamper-evident.
4. **Tenant isolation** is single-org today; multi-tenant needs row-level
   ownership + quotas before enterprise sales.

### Actions
```
1. Reorg + RPC-failure vitest suite (mocked provider)
2. Multi-RPC failover config + health metric
3. Audit-log service (append-only, hash-chained)
4. Tenant model: org_id on every row + middleware scoping
```

---

## Sub-agent 3 · Frontend / UX Specialist

**Verdict: 74/100 — good bones, buyer-facing story missing.**

### Verified strengths
- Next.js 16 + React 19 + wagmi + RainbowKit + TanStack Query + Radix;
  55 vitest tests; Playwright E2E; axe accessibility.
- `/v` public verification page exists ("no wallet needed to verify").
- `docs/design/dashboard_mockup.svg` + `verify_page_mockup.svg` define the
  target executive experience.

### Lagging
1. **Wallet-first framing.** The enterprise CISO does not want
   "Connect Wallet → Sign EIP-712". Make blockchain invisible: the
   dashboard should lead with readiness, not transactions.
2. **No executive report generation** (PDF board report).
3. **No PQC Passport view** — the single most compelling artifact for the
   market ("your company is X% quantum-ready, here's the evidence").
4. **Mobile is not designed** (CISO reads this on an iPad).

### Actions
1. Ship the mockups: Control Center as the landing page; wallet gated to
   the attest/relay flows only.
2. PQC Passport page: score, history, evidence chain, export PDF.
3. Responsive pass for dashboard + verification.

---

## Sub-agent 4 · ML / Planner Specialist

**Verdict: 88/100 — the real-data turnaround is the story of this cycle.**

### Verified strengths
- **Real-data trained flagship**: 13,058 real code files (openssl,
  boringssl, aws-lc, mbedtls, wolfssl, nodejs, golang, pyca…), 131 live
  TLS hosts → 39 real enterprise CBOMs, 401 real NVD CVEs.
- **X.509 encoder bug fixed** (`sha256WithRSAEncryption` was typed `SHA`,
  now `RSA`) with regression tests.
- **Tie-aware τ-b metric**: `model_real_v3.pt` scores **τ-b 0.807 on real
  CBOMs** (ceiling 0.855) and **τ 0.971 in-dist** — best on every suite.
- CodeBERTa fine-tuned on 10,294 real files (GPU, acc 0.953).
- HPO runs real objectives; QTrace-FM has a real masked-patch loss.

### Lagging
1. **Explainability is design-only** (STRATEGIC_ANALYSIS) — needs code:
   attribution of each rank to features/dependencies.
2. **No drift monitoring** on real CBOM distributions; retraining is manual.
3. **Migration-cost model remains synthetic** (honestly labeled) — the
   biggest moat opportunity: real cost/outcome telemetry.

### Actions
1. Recommendation cards: `why` (attribution), confidence, impact, rollback.
2. Drift detector on live scan distributions → alert + auto-retrain job.
3. SDK opt-in outcome telemetry (anonymized) → real cost model.

---

## Sub-agent 5 · SDK / Developer Experience Specialist

**Verdict: 84/100 — excellent SDK; missing CI-native entry points.**

### Verified strengths
- PyPI-published `qtrust` SDK: `did`, `vc` (Ed25519, fail-closed),
  `cbom_models`, `contracts`, `ipfs`, `risk`, `trust`, `client`.
- Cross-language VC compatibility proven both directions.
- Docs are unusually complete (ADR, runbooks, case studies).

### Lagging
1. **No GitHub Action wrapper** — enterprises want `uses: qtrust/scan`.
2. **No `qtrust scan .` CLI** as the primary DX (the inspector has a CLI;
   the SDK should wrap it for CI).
3. **No typed REST client** generated from OpenAPI.

### Actions
1. `qtrust-scan` GitHub Action (scan → CBOM → SARIF annotations).
2. SDK CLI: `qtrust scan`, `qtrust plan`, `qtrust verify`.
3. Generate typed client from `backend/openapi.yaml`; keep schema in CI.

---

## Sub-agent 6 · DevOps / Security Specialist

**Verdict: 80/100 — best-in-class CI for a prototype; gaps are production.**

### Verified strengths
- 8 workflows: CI, docs, Halmos, PQC self-scan, Docker, PyPI, release
  drafter, security (npm/pip audits, secret scanning).
- Reproducible model lineage (config, seed, data hash in checkpoints).

### Lagging
1. **No public deployment** — Base Sepolia addresses are the single
  biggest missing proof point.
2. **No fork / upgrade / reorg tests in CI** (see sub-agent 2).
3. **Placeholder security contact** — since replaced by
  `humoge7502.security@gmail.com` (see SECURITY.md).
4. **No chaos / disaster-recovery drill** for the read model.

### Actions
1. Sepolia deployment + on-chain verification + receipts committed.
2. CI gates: fork test, upgrade test, reorg test, storage-layout check.
3. Real security contact + security.txt.
4. DR runbook test: rebuild read model from chain in <1h.

---

## Sub-agent 7 · Compliance / Policy Specialist

**Verdict: 82/100 — engines exist; the *narrative* deadline is now.**

### Verified strengths
- NIST · CNSA 2.0 · FIPS · NIS2 · FISMA · FedRAMP · CMMC mapping in the
  policy engine; NVD-backed vendor readiness (401 CVEs).
- Copilot is honestly designed: **deterministic evidence, LLM only
  rephrases** (`copilot/llm.py` — "LLM explains, never decides").

### Lagging
1. **The market's clock is explicit** — NIST IR 8547 (deprecate 2030,
   disallow 2035), CNSA 2.0 (2027 vendor requirement / 2030 fielded
   equipment / 2035 NSS), FIPS 140-2 sunset Sep 2026, Google's 2029
   deadline. Q-Trust should *own* this calendar: compliance engine should
   output "days to each deadline" per asset class.
2. **FIPS 140-3 readiness** evidence story is not surfaced in the UI.
3. **No regulatory report templates** (CISA, EU NIS2, board-level).

### Actions
1. Add deadline-aware compliance output (days-to-X per framework).
2. "FIPS 140-3 ready" badge on evidence + passport.
3. Exportable compliance report per framework.

---

## Sub-agent 8 · Data / Moat Specialist

**Verdict: 86/100 — real-data corpus is the moat; make it the product.**

### Verified strengths
- Real corpus pipeline (`scripts/build_real_datasets.py`) is reproducible
  and now large (13K files, 131 hosts, 401 CVEs).
- Real-CBOM benchmark suite is a tracked fixture with an honest tie-aware
  protocol — the number to defend publicly.

### Lagging
1. **Migration-outcome telemetry** (the un-copyable data) is not collected.
2. **Corpus freshness**: scans are a point-in-time snapshot; add scheduled
  re-scans + drift diffs.
3. **No cross-enterprise anonymized benchmark** to publish.

### Actions
1. SDK telemetry opt-in: recommendation accepted/rejected → outcome → re-scan.
2. Cron re-scan of the 131-host corpus; version the dataset.
3. Publish a "PQC readiness of the top-131" public report (PR value).

---

## Sub-agent 9 · Competitive Positioning Specialist

**Verdict: 68/100 — differentiation is real but not yet *sold*.**

### Verified landscape (Aug 2026 research)
- **Enterprise incumbents**: Keyfactor (crypto-agility platform),
  DigiCert Quantum Central (discover → prioritize → remediate → prove;
  launched ~Jul 2026), IBM Quantum Safe (discovery + orchestration).
- **Vendors**: PQShield, SandboxAQ, Quantinuum, QuSecure — all
  commercial, none open-source, none with *verifiable on-chain evidence*.
- **Open ecosystem**: IBM CBOM (CycloneDX-upstreamed), CycloneDX v1.7 /
  ECMA-424 standardizes CBOM — **CBOM is commodity; it is not the moat.**
- Market stats: 87% of orgs pursue PQC, only 7% deploy at scale (DigiCert
  2026 survey) — massive whitespace, urgent need, weak incumbent
  execution on evidence.

### Where Q-Trust is ahead
1. **Verifiable evidence layer** (nobody else anchors evidence on-chain).
2. **Open source + SDK** (enterprises can run it themselves).
3. **Real-data ML** (τ-b 0.807 on real CBOMs) with honest methodology.
4. **Cost**: commercial platforms $100K–$500K; Q-Trust is OSS.

### Where Q-Trust lags
1. **No audit / no public deployment** → cannot win regulated deals yet.
2. **No enterprise integrations** (Jira/ServiceNow/SIEM/CMDB/GitHub).
3. **No executive reporting / passport** → buyers can't *see* the value.
4. **Zero community signal** (0 stars/forks visible) → trust deficit.

### Actions
1. Ship the passport + public verification (killer demo).
2. Publish the Sepolia deployment + audit → deal-ready evidence.
3. GitHub App + Jira integration (continuous scan = continuous value).
4. Drive community: publish the top-131 readiness report; add
   `good-first-issue`; enable discussions.

---

## Technology research — what to adopt next (Aug 2026)

| Technology | Why | Priority |
| --- | --- | --- |
| **CycloneDX v1.7 CBOM (ECMA-424)** | Standard taxonomy; align our CBOM emitter so we interoperate with IBM CBOM kit + CycloneDX tooling | Now |
| **FIPS 203/204/205 targets in recommendations** | Planner should rank *target algorithms* (ML-KEM-768, ML-DSA-65), not just "leave RSA" | Now |
| **FIPS 140-2 sunset (Sep 2026) / FIPS 140-3** | Real market deadline; surface readiness in UI + passport | Now |
| **NIST IR 8547 + CNSA 2.0 calendar** | Deadline-aware compliance output (days-to-X) | Now |
| **W3C VC 2.1 + BBS+ selective disclosure** | Prove *parts* of a credential without revealing all claims — natural fit for compliance VCs | P1 |
| **Zero-knowledge compliance proofs** | Prove PQC-readiness without revealing inventory; ZK is entering compliance stacks in 2026 | P2 (spike) |
| **Passkeys + SSO (OIDC/SAML)** | Remove wallet friction; enterprise identity first-class | P1 |
| **Kubernetes-native discovery** | K8s operator/cron scanner — concrete integration enterprises ask for | P1 |
| **Multi-chain anchoring (Base → Ethereum)** | Batch evidence roots to Ethereum Mainnet for durability | P2 |
| **LLM explanation layer (keep deterministic core)** | Already architected correctly; ship the explainer UI | P1 |

---

## 90-day exit criteria (unified)

- [ ] External audit engaged; findings remediated; report in `docs/audits/`
- [ ] Registries deployed + verified on Base Sepolia; receipts committed
- [ ] Governance behind Safe 2/3 → 7-day Timelock; relayer key in KMS
- [ ] Real-CBOM τ-b regression gate in CI (doctrine benchmark)
- [ ] PQC Passport + executive report shipped
- [ ] GitHub App + Jira/ServiceNow integration live
- [ ] Explainability cards + drift monitoring + outcome telemetry
- [ ] Fork / upgrade / reorg / storage-layout tests in CI
- [ ] Top-131 public readiness report published
