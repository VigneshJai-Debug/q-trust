# Q-Trust — 30/60/90 Day Execution Plan

**Rule:** Execute. Do not read more analysis. Do not add features. Do not improve the GNN.

---

## Day 1-7: Critical fixes

- [ ] **Day 1-2:** Fix F1 (proxy mismatch). Switch `contracts/script/Deploy.s.sol` from `TransparentUpgradeableProxy` to `ERC1967Proxy` (UUPS-compatible, no admin parameter). Verify `forge test` passes 51/51. Add `UpgradeAuth.t.sol` test.
- [ ] **Day 3:** Acquire Base Sepolia faucet ETH (https://www.base.org/faucet or equivalent). Target: ≥0.5 testnet ETH in deployer wallet.
- [ ] **Day 4-5:** Deploy to Base Sepolia. Run `forge script script/Deploy.s.sol --rpc-url <base-sepolia-rpc> --broadcast`. Verify contracts on Basescan. Update `README.md` with deployed addresses.
- [ ] **Day 6:** Update `README.md` and `scripts/verify_all.sh` test count (49 → 51). Use `forge test --json | jq '.summary.test_results | length'` to avoid future staleness.
- [ ] **Day 7:** Add GitHub Actions CI/CD pipeline:
  - Job 1: `cd contracts && forge build && forge test`
  - Job 2: `cd sdk && python -m pytest -q`
  - Job 3: `cd backend && npm run build`
  - Job 4: `cd frontend && npm run build`
  - Job 5: `cd planner && python -m qtrust_planner.benchmark --seeds 42 --epochs 5`
  - Add green status badge to README.

---

## Day 8-30: Patent + first customer conversations (parallel)

### Patent track (Day 8-21)
- [ ] **Day 8-10:** Engage registered patent attorney or agent (USPTO-registered). Send them `docs/PATENT/{invention_disclosure,draft_claims,prior_art_survey,filing_checklist}.md`.
- [ ] **Day 11-14:** Complete disclosure audit. Confirm inventor names. Document any prior public disclosures (repo date, demos, thesis drafts). Confirm ownership (employer / university IP policy if applicable).
- [ ] **Day 15-18:** Produce 2-4 patent figures (system architecture, registry data-flow, GNN architecture, claim-mapping table).
- [ ] **Day 19-21:** File US provisional patent via USPTO EFS-Web (micro-entity fee $65-260 + counsel fees $1.5-3k). Lock priority date.
- [ ] **Day 21-30:** Begin PCT preparation (file within 12 months for international rights).

### Customer track (Day 8-30, parallel)
- [ ] **Day 8-14:** Build lead list of 50 US credit union CISOs in $1B-$10B AUM range. Sources: NCUA.gov, CUNA, credit union websites, LinkedIn.
- [ ] **Day 15-21:** Cold-email all 50 with this offer:

  > Subject: Free PQC migration assessment — 10-minute scan of your public TLS endpoints
  >
  > Hi [CISO name],
  >
  > I'm [founder], building Q-Trust — the on-chain trust infrastructure for post-quantum cryptography migration compliance. With NCUA Part 748 + CISA + OMB M-23-02 all mandating PQC readiness, I'm offering 5 free PQC migration assessments to credit unions.
  >
  > Here's what you get in 10 minutes:
  > - A scan of your public TLS endpoints (firsttechfcu.org, online banking, mobile API)
  > - A Cryptographic Bill of Materials (CBOM) showing every cryptographic asset
  > - A priority-ranked migration plan from our trained Graph Neural Network
  > - The CBOM hash anchored on Base L2 (free for the first 5 credit unions)
  >
  > No commitment, no sales call. Just the assessment. Want me to run it?
  >
  > [Founder name]
  > [LinkedIn]

- [ ] **Day 22-28:** Book 10 demos. Run 10 scans. Convert 3 to free pilots. Get written permission before scanning.
- [ ] **Day 29-30:** Publish 1 case study (anonymized if needed). Example structure:
  > "First Tech FCU identified 12 RSA-2048 TLS certificates and 3 ECC-P256 SSH host keys via Q-Trust's inspector. The GNN planner recommended migrating the SSH keys first because vendor support for ML-DSA-441 SSH was available. Migration completed in 6 weeks."

### Co-founder track (Day 8-30, parallel)
- [ ] **Day 8-14:** Build candidate list of 50+ enterprise security sales professionals. Sources: LinkedIn (ex-Keyfactor, ex-Venafi, ex-CrowdStrike, ex-Palo Alto Networks, ex-Wiz, ex-SentinelOne). Filter for: 5+ years enterprise sales, security/crypto background, recently laid-off or looking.
- [ ] **Day 15-21:** Send 50 personalized outreach messages. Pitch: "I've built Q-Trust (post-quantum migration coordination protocol on Base L2). Patent docs drafted. Need co-founder with enterprise security sales experience for YC application. Equity + salary post-raise."
- [ ] **Day 22-30:** Interview 5-10 candidates. Goal: 1 co-founder committed by Day 90.

---

## Day 31-60: First paying customer + audit kickoff

- [ ] **Day 31-45:** Convert 1 of 3 pilots to paid ($25k/year). Sign 2 more LOIs for next quarter.
- [ ] **Day 31-45 (parallel):** Commission Trail of Bits smart-contract audit. Budget $15-25k, 4-6 week lead time. Provide scope: 5 contracts + Deploy.s.sol + governance. Fix F1 first (Day 1-2).
- [ ] **Day 31-45 (parallel):** Add frontend RBAC. Implement `useOrgRole()` and `useVendorRole()` hooks in `frontend/src/components/dynamic-provider.tsx`. Gate dashboard and vendor portal on role check.
- [ ] **Day 31-45 (parallel):** Add attack test suite. Create `contracts/test/Attack.t.sol` covering: reentrancy, proxy upgrade auth, pause bypass, cross-registry reentrancy.
- [ ] **Day 46-60:** Record 5-minute demo video on live Base Sepolia. Script:
  - 0:00-0:30 — Problem (NIST PQC mandate, $X cost of compliance today)
  - 0:30-1:30 — Demo: scan a credit union's TLS endpoint, produce CBOM
  - 1:30-2:30 — Demo: register CBOM on Base Sepolia via EIP-712 gasless attestation
  - 2:30-3:30 — Demo: GNN migration plan
  - 3:30-4:30 — Demo: public verification page (/v/asset-id)
  - 4:30-5:00 — Customer quote + ask
- [ ] **Day 46-60 (parallel):** Cold-email 20 PQC-ready vendors (DigiCert, Thales, Entrust, AWS KMS, Cloudflare, Google Trust Services, Microsoft). Offer: free vendor registration. Goal: 1 vendor attests on-chain.
- [ ] **Day 46-60 (parallel):** Cold-email 10 audit firms (Trail of Bits, NCC Group, OpenZeppelin, Spearbit, Hacken, Halborn). Offer: free auditor registration. Goal: 1 auditor posts attestation on-chain.
- [ ] **Day 60:** Submit YC application for next batch. (Check deadline at ycombinator.com/apply.)

---

## Day 61-90: Traction + audit completion + raise prep

- [ ] **Day 61-75:** Audit findings remediated. Re-audit if needed.
- [ ] **Day 61-75 (parallel):** Sign 2-3 more paying customers. Total: 3-5 paying customers.
- [ ] **Day 61-75 (parallel):** Co-founder onboarded (if not already).
- [ ] **Day 76-90:** Publish case studies (2-3 total).
- [ ] **Day 76-90 (parallel):** Demo at 1 conference (NCUA, CUNA, RSA, Black Hat, or local security meetup).
- [ ] **Day 76-90 (parallel):** Start SOC 2 Type II observation period (engage Vanta + Drata + CPA firm).
- [ ] **Day 76-90 (parallel):** Begin pre-seed raise conversations. Target: $1-2M at $8-12M post-money cap. Pitch deck structure:
  1. Problem (NIST PQC mandate, cost of compliance)
  2. Solution (Q-Trust: 4-registry protocol on Base L2)
  3. Traction (3-5 paying customers, $75-150k ARR)
  4. Market ($75M ARR addressable in credit unions; $2-5B globally by 2030)
  5. Moat (patent filed, three-sided network effects, on-chain history)
  6. Team (founder + co-founder)
  7. Ask ($1-2M pre-seed, 18-month runway)

---

## What to STOP doing (re-stated)

- **Stop adding features.** No W3C VCs, no AI-agent trust, no multi-chain, no ZK proofs. Those are Year 2-3 work.
- **Stop improving the GNN.** Ship the heuristic as default planner. Re-train GNN only after 50+ real CBOMs.
- **Stop writing documentation.** The 5,160-line `QTrust_Implementation_Guide.md` is out of sync. Replace with 200-line `ARCHITECTURE.md`.
- **Stop reading more analysis.** You have 6,700 lines of analysis across 2 documents. Execute instead.
- **Stop considering a token.** No token. Charges in USD or ETH.

---

## Day 90 success criteria

At day 90, you should have:

- [ ] Live deployment on Base Sepolia (Basescan-verified)
- [ ] CI/CD pipeline running green
- [ ] US provisional patent filed
- [ ] Smart-contract audit completed (Trail of Bits)
- [ ] 3-5 paying customers ($75-150k ARR)
- [ ] 2-3 vendor attestation partners (1+ paying)
- [ ] 1-2 auditor partners (1+ posting attestations)
- [ ] 2-3 case studies published
- [ ] 1 conference demo delivered
- [ ] Co-founder onboarded
- [ ] 5-minute demo video recorded
- [ ] YC application submitted (if next batch aligns)
- [ ] 20+ investor conversations begun

**If you hit these 13 items, you are in the top 10% of YC applicants and a credible pre-seed raise is straightforward. If you skip them and build more features instead, you will be in the bottom 50%.**

---

## Investor objection prep (memorize these)

| Objection | Response |
|---|---|
| "Blockchain is unnecessary; a database works." | Database requires trusted operator. Q-Trust provides cross-org non-repudiation. Regulators require this. |
| "Microsoft Entra / Google Identity already does this." | They are single-vendor identity systems, not cross-org compliance protocols. They don't interoperate. |
| "The GNN doesn't beat the heuristic." | GNN is a feature, not the moat. Heuristic is default. GNN validated on real data when we have 50+ CBOMs. |
| "Credit unions don't buy from startups." | They do — First Tech FCU, Alliant, BECU have early-adopter culture. We have [N] paying. |
| "Solo founder; can't build a company." | Co-founder onboarded Day 75. [Name], ex-[security company] with enterprise sales experience. |
| "Public repo before patent; international rights lost." | US 12-month grace period. US provisional filed Day 21. PCT within 12 months. |
| "Competitors (Keyfactor, Venafi) can copy." | Patent on combination. Network effects. First-mover in credit-union wedge. On-chain history unreplicable. |
| "Token / regulatory risk." | No token. Charges in USD or ETH. No SEC/MiCA exposure. |
| "Cold-start failure: 3-sided marketplaces are hard." | Credit unions first (one side). Vendors subsidized (free for first 10). Anchor auditor: Trail of Bits. |
| "Why now?" | NIST PQC + OMB M-23-02 + CISA + EU NIS2 all converge 2024-2026. Window closes by 2028. |

---

## Final word

**Execute. Do not analyze.** The architecture is sound. The audit is done (twice). The patent docs are drafted. The roadmap is clear.

The next 90 days decide whether Q-Trust is a footnote or a company.

---

*This is a 1-page action plan, intentionally short. The full analysis is in `QTrust_Comprehensive_Assessment_Post_P0.md` (2,169 lines) and `QTrust_2030_Blueprint.md` (4,530 lines). Do not read those until this checklist is complete.*
