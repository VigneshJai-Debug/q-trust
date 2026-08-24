# 4. Postgres read model with direct-RPC fallback

## Status

Accepted — 2026-08-24

## Context

The API needs paginated lists, per-org summaries, and latest-audit lookups.
Answering these from JSON-RPC `eth_getLogs` calls is slow, rate-limited, and
cannot express pagination cleanly — but making Postgres mandatory adds a hard
operational dependency for anyone running the stack locally.

## Decision

The blockchain remains the source of truth. A lightweight indexer
(`backend/src/services/indexer.ts`) materializes the four registries' events
into Postgres tables with upsert-on-conflict semantics and per-stream cursors
(`indexer_state`), plus a `processed_blocks` table used for reorg detection:
recent block hashes are re-checked against canonical chain state, and on a
mismatch rows at/after the fork point are purged and the cursor rewound so
backfill replays them. Live events wait N confirmations before being applied.

Every read service checks Postgres first and falls back to direct RPC reads
when the DB is absent/unavailable — the API degrades in capability (no deep
pagination), not availability.

Consequences:

* Fast dashboards and pagination without indexing infrastructure beyond one
  Postgres container.
* Event-sourced rebuild: dropping all rows and replaying from genesis
  reproduces identical state (see backup-restore drill).
* Reorg safety depends on confirmation depth vs Base's shallow reorgs;
  defaults (12 blocks) chosen accordingly.
* Dual read paths mean two code paths to test; fallback behavior is covered by
  service-level tests.
