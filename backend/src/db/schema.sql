-- Q-Trust indexer schema (Postgres).
-- The blockchain remains the source of truth; this is a read model for fast,
-- paginated, filtered API responses.

CREATE TABLE IF NOT EXISTS assets (
    asset_id      TEXT PRIMARY KEY,
    org_did       TEXT NOT NULL,
    cbom_hash     TEXT NOT NULL,
    metadata_uri  TEXT NOT NULL DEFAULT '',
    timestamp     BIGINT NOT NULL,
    last_updated  BIGINT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    tx_hash       TEXT NOT NULL DEFAULT '',
    block_number  BIGINT NOT NULL DEFAULT 0,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assets_org ON assets (org_did);

CREATE TABLE IF NOT EXISTS attestations (
    attestation_id TEXT PRIMARY KEY,
    vendor_did     TEXT NOT NULL,
    product_id     TEXT NOT NULL,
    version        TEXT NOT NULL,
    algorithm      TEXT NOT NULL,
    supported      BOOLEAN NOT NULL,
    evidence_uri   TEXT NOT NULL DEFAULT '',
    timestamp      BIGINT NOT NULL,
    revoked        BOOLEAN NOT NULL DEFAULT FALSE,
    tx_hash        TEXT NOT NULL DEFAULT '',
    block_number   BIGINT NOT NULL DEFAULT 0,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_att_vendor ON attestations (vendor_did);
CREATE INDEX IF NOT EXISTS idx_att_product ON attestations (product_id, version, algorithm);

CREATE TABLE IF NOT EXISTS migrations (
    migration_id   TEXT PRIMARY KEY,
    asset_id       TEXT NOT NULL,
    org_did        TEXT NOT NULL,
    from_algorithm TEXT NOT NULL,
    to_algorithm   TEXT NOT NULL,
    evidence_hash  TEXT NOT NULL,
    evidence_uri   TEXT NOT NULL DEFAULT '',
    timestamp      BIGINT NOT NULL,
    verified       BOOLEAN NOT NULL DEFAULT FALSE,
    tx_hash        TEXT NOT NULL DEFAULT '',
    block_number   BIGINT NOT NULL DEFAULT 0,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mig_org ON migrations (org_did);
CREATE INDEX IF NOT EXISTS idx_mig_asset ON migrations (asset_id);

CREATE TABLE IF NOT EXISTS audits (
    audit_id        TEXT PRIMARY KEY,
    org_did         TEXT NOT NULL,
    auditor_did     TEXT NOT NULL,
    result          INTEGER NOT NULL,
    assets_reviewed BIGINT NOT NULL,
    assets_migrated BIGINT NOT NULL,
    report_hash     TEXT NOT NULL,
    report_uri      TEXT NOT NULL DEFAULT '',
    timestamp       BIGINT NOT NULL,
    tx_hash         TEXT NOT NULL DEFAULT '',
    block_number    BIGINT NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_org ON audits (org_did);

-- Chain cursor: last block processed per contract/event.
CREATE TABLE IF NOT EXISTS indexer_state (
    key        TEXT PRIMARY KEY,
    block      BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);