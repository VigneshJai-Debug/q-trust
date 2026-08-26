/**
 * Backend API client used by the frontend.
 *
 * All requests go to the Q-Trust Fastify backend (default: same origin in prod,
 * or http://localhost:3001 in dev). The base URL is configurable via the
 * NEXT_PUBLIC_QTRUST_API_URL env var.
 */
export const API_BASE_URL =
  process.env.NEXT_PUBLIC_QTRUST_API_URL ?? "http://localhost:3001";

export interface AssetInfo {
  asset_id: string;
  org_did: string;
  cbom_hash: string;
  metadata_uri: string;
  timestamp: number;
  last_updated: number;
  active: boolean;
}

export interface AssetVerification {
  asset_id: string;
  exists: boolean;
  active: boolean;
  org_did: string;
  chain_id: number;
  chain_name: string;
  verified_at: number;
}

export interface VendorAttestationInfo {
  attestation_id: string;
  vendor_did: string;
  product_id: string;
  version: string;
  algorithm: string;
  supported: boolean;
  evidence_uri: string;
  timestamp: number;
  revoked: boolean;
}

export interface MigrationProgressInfo {
  org_address: string;
  total_migrations: number;
  verified_migrations: number;
  unverified_migrations: number;
  fetched_at: number;
  // Indexer-enhanced fields (optional — present when served from Postgres)
  asset_count?: number;
  attestation_count?: number;
}

export interface MigrationInfo {
  migration_id: string;
  asset_id: string;
  org_did: string;
  from_algorithm: string;
  to_algorithm: string;
  evidence_hash: string;
  evidence_uri: string;
  timestamp: number;
  verified: boolean;
}

export interface LatestAuditInfo {
  org_address: string;
  exists: boolean;
  result: string;
  result_code: number;
  timestamp: number;
}

export interface OrgMigrationsResponse {
  org: string;
  progress: MigrationProgressInfo;
  migrations: MigrationInfo[];
  latest_audit: LatestAuditInfo;
}

// Backend may return paginated shape ({ items, total, ... }) for org assets/vendors.
// These interfaces capture both the legacy flat array shape and the paginated
// Page shape so the frontend can handle either without breaking (schema drift guard).
export interface Paginated<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}

export interface VendorAttestationsResponse {
  vendor: string;
  count: number;
  attestations: VendorAttestationInfo[];
  // Paginated alternative (new backend shape: vendor + Page)
  items?: VendorAttestationInfo[];
  total?: number;
}

export interface ProductSupportInfo {
  supported: boolean;
  vendor_did: string;
  attestation_id: string | null;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const response = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    let detail = "";
    try {
      const body = await response.json();
      detail = body.detail ?? body.error ?? JSON.stringify(body);
    } catch {
      detail = await response.text();
    }
    throw new Error(`API ${response.status}: ${detail}`);
  }

  return (await response.json()) as T;
}

/** Fetch an asset by ID (read-only, cacheable). */
export function fetchAsset(assetId: string): Promise<AssetInfo> {
  return apiFetch<AssetInfo>(`/v1/assets/${encodeURIComponent(assetId)}`);
}

/** Verify an asset's status (read-only). */
export function fetchAssetVerification(assetId: string): Promise<AssetVerification> {
  return apiFetch<AssetVerification>(`/v1/assets/${encodeURIComponent(assetId)}/verify`);
}

/** Fetch all attestations posted by a vendor. Resilient to paginated vs legacy shape (schema drift). */
export async function fetchVendorAttestations(
  vendorAddress: string,
): Promise<VendorAttestationsResponse> {
  const raw = await apiFetch<Record<string, unknown> & VendorAttestationsResponse & Paginated<VendorAttestationInfo>>(
    `/v1/vendors/${encodeURIComponent(vendorAddress)}/attestations`,
  );
  // New shape: { vendor, items, total, offset, limit } — normalize to legacy { vendor, count, attestations }
  if (Array.isArray((raw as unknown as { items?: unknown }).items)) {
    const items = (raw as unknown as { items: VendorAttestationInfo[] }).items;
    const total = (raw as unknown as { total?: number }).total ?? items.length;
    return {
      vendor: (raw as unknown as { vendor: string }).vendor ?? vendorAddress,
      count: total,
      attestations: items,
      items,
      total,
    };
  }
  // Legacy shape already has attestations/count — ensure both fields present
  const attestations = Array.isArray(raw.attestations) ? raw.attestations : [];
  const count = typeof raw.count === "number" ? raw.count : attestations.length;
  return { vendor: raw.vendor ?? vendorAddress, count, attestations };
}

/** Fetch an org's migration progress. Handles migrations as array vs Page (schema drift). */
export async function fetchOrgMigrations(orgAddress: string): Promise<OrgMigrationsResponse> {
  const raw = await apiFetch<Record<string, unknown> & OrgMigrationsResponse & { migrations?: unknown }>(
    `/v1/orgs/${encodeURIComponent(orgAddress)}/migrations`,
  );
  let migrations: MigrationInfo[] = [];
  const m = (raw as unknown as { migrations?: unknown }).migrations;
  if (Array.isArray(m)) {
    migrations = m as MigrationInfo[];
  } else if (m && typeof m === "object" && Array.isArray((m as { items?: unknown }).items)) {
    migrations = (m as Paginated<MigrationInfo>).items;
  }
  return {
    org: (raw as unknown as { org: string }).org ?? orgAddress,
    progress: (raw as unknown as { progress: MigrationProgressInfo }).progress,
    migrations,
    latest_audit: (raw as unknown as { latest_audit: LatestAuditInfo }).latest_audit,
  };
}

/** Fetch the assets registered by an org (full records). Handles array vs paginated Page. */
export async function fetchOrgAssets(orgAddress: string): Promise<AssetInfo[]> {
  const raw = await apiFetch<unknown>(`/v1/orgs/${encodeURIComponent(orgAddress)}/assets`);
  if (Array.isArray(raw)) return raw as AssetInfo[];
  if (raw && typeof raw === "object") {
    const r = raw as Record<string, unknown>;
    if (Array.isArray(r.items)) return r.items as AssetInfo[];
    if (Array.isArray(r.assets)) return r.assets as AssetInfo[];
    // Some indexer responses nest under "assets" key
    if (Array.isArray((r as unknown as { data?: unknown }).data)) return (r as unknown as { data: AssetInfo[] }).data;
  }
  return [];
}

/** Check whether a product+version supports a PQC algorithm on-chain. */
export function checkProductSupport(
  productId: string,
  version: string,
  algorithm: string,
): Promise<{ supported: boolean; vendor_did: string; attestation_id: string | null }> {
  return apiFetch(
    `/v1/products/${encodeURIComponent(productId)}/support?version=${encodeURIComponent(version)}&algorithm=${encodeURIComponent(algorithm)}`,
  );
}

/** Fetch a vendor's current EIP-712 nonce for gasless attestations. */
export async function fetchVendorNonce(vendorAddress: string): Promise<number> {
  const data = await apiFetch<{ nonce: string }>(
    `/v1/relay/nonce/${encodeURIComponent(vendorAddress)}`,
  );
  return Number(data.nonce);
}

/** Submit a gasless EIP-712 attestation through the backend relayer. */
export async function relayAttestation(payload: {
  productId: string;
  version: string;
  algorithm: string;
  supported: boolean;
  evidenceURI: string;
  nonce: number;
  signature: string;
}): Promise<{ txHash: string; vendorDid: string; attestationId: string }> {
  const res = await fetch(`${API_BASE_URL}/v1/relay/attestation`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error ?? `Relay failed with status ${res.status}`);
  }
  return json;
}

/** Request a migration plan from the AI planner (via the backend proxy). */
export async function fetchMigrationPlan(payload: {
  cbom: Record<string, unknown>;
  deadline?: string;
}): Promise<{
  migration_order: Array<{
    rank: number;
    asset_id: string;
    algorithm: string;
    criticality: string;
    pqc_ready: boolean;
    risk_score: number;
    migrate_days: number;
  }>;
  schedule?: {
    feasible: boolean;
    days_available: number;
    total_effort_days: number;
    suggested_daily_rate: number | null;
    windows: Array<{ asset_id: string; start: string; end: string }>;
  } | null;
  total_assets: number;
}> {
  const res = await fetch(`${API_BASE_URL}/v1/plans`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error ?? `Planner request failed with status ${res.status}`);
  }
  return json;
}

/** Subscribe to webhook notifications. */
export function subscribeWebhook(
  address: string,
  url: string,
  secret: string,
  events: string[] = ["*"],
): Promise<{ subscribed: boolean; subscriber: unknown }> {
  return apiFetch(`/v1/webhooks/subscribe`, {
    method: "POST",
    body: JSON.stringify({ address, url, secret, events }),
  });
}

/**
 * Fetch IPFS metadata (CORS-enabled public gateway by default).
 * Pass a custom gateway via NEXT_PUBLIC_IPFS_GATEWAY.
 */
export async function fetchIpfsJson(cidOrUri: string): Promise<Record<string, unknown> | null> {
  const gateway = process.env.NEXT_PUBLIC_IPFS_GATEWAY ?? "https://ipfs.io/ipfs/";
  const cid = cidOrUri.replace(/^ipfs:\/\//, "");
  const url = `${gateway}${cid}`;
  try {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) return null;
    return (await response.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** The list of NIST-standardized PQC algorithms for vendor attestation forms. */
export const PQC_ALGORITHMS = [
  { value: "ML-KEM-512", label: "ML-KEM-512 (NIST FIPS 203, Category 1)" },
  { value: "ML-KEM-768", label: "ML-KEM-768 (NIST FIPS 203, Category 3)" },
  { value: "ML-KEM-1024", label: "ML-KEM-1024 (NIST FIPS 203, Category 5)" },
  { value: "ML-DSA-441", label: "ML-DSA-441 (NIST FIPS 204, Category 2)" },
  { value: "ML-DSA-659", label: "ML-DSA-659 (NIST FIPS 204, Category 3)" },
  { value: "ML-DSA-877", label: "ML-DSA-877 (NIST FIPS 204, Category 5)" },
  { value: "SLH-DSA-SHA2-128s", label: "SLH-DSA-SHA2-128s (NIST FIPS 205, Category 1)" },
  { value: "SLH-DSA-SHA2-128f", label: "SLH-DSA-SHA2-128f (NIST FIPS 205, Category 1)" },
  { value: "SLH-DSA-SHA2-192s", label: "SLH-DSA-SHA2-192s (NIST FIPS 205, Category 3)" },
  { value: "SLH-DSA-SHA2-192f", label: "SLH-DSA-SHA2-192f (NIST FIPS 205, Category 3)" },
  { value: "SLH-DSA-SHA2-256s", label: "SLH-DSA-SHA2-256s (NIST FIPS 205, Category 5)" },
  { value: "SLH-DSA-SHA2-256f", label: "SLH-DSA-SHA2-256f (NIST FIPS 205, Category 5)" },
  { value: "HQC-128", label: "HQC-128 (NIST FIPS 230, Category 1)" },
  { value: "HQC-192", label: "HQC-192 (NIST FIPS 230, Category 3)" },
  { value: "HQC-256", label: "HQC-256 (NIST FIPS 230, Category 5)" },
  { value: "FALCON-512", label: "Falcon-512 (Category 1)" },
  { value: "FALCON-1024", label: "Falcon-1024 (Category 5)" },
] as const;
