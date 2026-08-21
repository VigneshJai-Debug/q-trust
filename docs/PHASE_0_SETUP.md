# Phase 0: Environment Setup

## Objectives
- Set up BrevLab instance
- Install Foundry, Node.js, Python env
- Configure MetaMask with Base Sepolia
- Create project structure

## Status
- [x] Foundry installed (forge 1.7.1)
- [x] Node.js installed (v20.20.2) + npm
- [x] Python installed (3.13.12) + qiskit/torch env
- [x] Project structure created (contracts/, sdk/, inspector/, planner/, backend/, frontend/, notebooks/, pilot/, docs/)
- [~] MetaMask / wallet configured — deployer key from anvil used locally; real Base Sepolia requires a funded wallet

## Verification
- `forge --version`, `node --version`, `python3 --version` all pass
- Local chain: anvil (http://127.0.0.1:8545, chain-id 84532) — all phases verified against it