# Contributing to Q-Trust

## Welcome

Thank you for your interest in contributing to Q-Trust. This protocol helps organizations coordinate the migration from classical to post-quantum cryptography. Every contribution — code, documentation, bug reports, feature ideas — is valuable.

## Getting Started

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/<your-username>/q-trust.git
cd q-trust
git remote add upstream https://github.com/humoge7502/q-trust.git
```

### Prerequisites

- Node.js 20+
- Python 3.10+
- Foundry (for Solidity tooling)
- Docker (for integration tests)

### Development Setup

```bash
# Install dependencies
npm install

# Install Foundry (if not already installed)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install Python dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
# Edit .env with your local configuration

# Compile contracts
cd contracts && forge build && cd ..

# Run all linters
npm run lint
```

## Repository Structure

```
q-trust/
├── contracts/      Solidity smart contracts (Base L2, UUPS proxies)
├── sdk/            Python SDK for scanner, risk engine, and planner
├── inspector/      Cryptographic asset scanner (source code, TLS, packages)
├── planner/        AI migration planner (GCN + GAT model)
├── backend/        Node.js API server and relayer network
├── frontend/       Web dashboard (React, TypeScript)
├── scripts/        Deployment, verification, and CI scripts
└── docs/           Whitepaper, architecture, API docs
```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make your changes.

3. Run tests for the component you modified.

4. Run linters and typecheck.

5. Submit a pull request against `main`.

## Testing

Each component has its own test suite:

| Component | Command |
|-----------|---------|
| Contracts | `cd contracts && forge test` |
| SDK | `cd sdk && pytest` |
| Inspector | `cd inspector && pytest` |
| Planner | `cd planner && pytest` |
| Backend | `cd backend && npm test` |
| Frontend | `cd frontend && npm test` |
| Full stack | `./scripts/verify_all.sh` |

## Code Style

### Solidity

- Version: 0.8.24
- Follow OpenZeppelin conventions
- Use NatSpec for all public/external functions
- Inherit from `Initializable`, `UUPSUpgradeable`, `AccessControlUpgradeable` where appropriate
- No hardcoded addresses — use constructor/initializer parameters

### Python

- Linter: ruff (`ruff check .`)
- Type hints on all function signatures
- Pydantic models for data structures
- Docstrings in Google style

### TypeScript

- Strict mode enabled
- ESLint with the project config
- Prefer `readonly` for immutable data
- Use `interface` over `type` for object shapes

## Security

- **Never commit secrets, private keys, or API tokens.** Use environment variables.
- **Never store keys in code or config files.** Use hardware security modules or key vaults.
- **All admin operations go through the governance TimelockController.** No bypasses.
- **Report vulnerabilities** to security@qtrust.dev. Do not open public issues for security bugs.
- **Run `npm audit` and `pip audit`** before submitting security-sensitive changes.

## Pull Request Process

1. Fill out the PR template completely.
2. Include tests for new features or bug fixes.
3. Update documentation if you change behavior or add functionality.
4. Link related issues using `Closes #<issue>` or `Refs #<issue>`.
5. Ensure all CI checks pass before requesting review.
6. Request review from a maintainer familiar with the affected component.

## Architecture Decisions

### Why Base L2

Base is an Ethereum L2 with sub-cent transaction costs and full EVM compatibility. This lets us use Solidity, Hardhat/Foundry, and the existing Ethereum ecosystem without compromising on security. The L2 inherits Ethereum's consensus security while providing the throughput needed for high-frequency attestation writes.

### Why UUPS Proxy Upgradeability

Smart contracts on-chain cannot be modified after deployment. UUPS proxies let us upgrade contract logic while preserving storage layout. The `TimelockController` governance layer ensures upgrades go through a delay period, giving the community time to review changes before execution.

### Why CycloneDX 1.7

CycloneDX is an OWASP standard for Software Bill of Materials (SBOM) and Cryptographic Bill of Materials (CBOM). Version 1.7 introduced explicit cryptographic property support, making it the industry standard for PQC inventory. Using CBOM ensures interoperability with existing security tooling and regulatory reporting.

### Why Hash-Chained Evidence

Hash chaining creates a tamper-evident sequence: every evidence record includes the hash of the previous record. This means any modification to historical records is immediately detectable. Combined with on-chain root anchoring, this provides cryptographic proof of evidence integrity without requiring a blockchain write for every individual record.

## Anti-Decay Checklist (Engineering Elevation Blueprint §A.4)

Every PR must defend the gains from decaying — the same mechanism that keeps the 7 CI workflows honest:

- [ ] Every badge resolves. Link-check the README in the docs workflow; a badge is a claim.
- [ ] Every number has a source link. New metrics enter `docs/_data/metrics.json` first, prose second; a number without a source link does not merge.
- [ ] One metric, one value. If the same quantity appears in two documents, one of them imports it or one of them is deleted. The 127/189 → 211 test-count incident is the cautionary tale.
- [ ] Zero superlatives, zero unverifiable claims. Reviewer check on every README/docs PR.
- [ ] Limitations stay stated. When a Reality-check item is fixed (external audit obtained, contracts deployed), the section updates — it never silently disappears.
- [ ] Screenshots are real and current. A UI PR that changes a landing-page-visible surface re-captures the asset in the same PR.
- [ ] Reference material is generated, never hand-copied. API tables render from `openapi.yaml`; env tables from `.env.example`.
- [ ] No binaries in git. `pre-commit`'s 500 KB cap is absolute; artifacts ride Releases. Run `git ls-files | xargs ls -lh | grep -E "\.pt|\.pdf"` before merge.
