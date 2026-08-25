/**
 * Relayer service — writes attestations to the Q-Trust contracts with the
 * configured relayer account (QTRUST_RELAYER_PRIVATE_KEY — required; the
 * deployer key is NEVER used for runtime transactions).
 *
 * Also implements EIP-712 gasless attestations: vendors sign typed data
 * off-chain (SDK sign_attestation / MetaMask); the relayer verifies the
 * signature, recovers the signer, and submits it — vendors never need to
 * hold funds or run a node. The contract records the SIGNER as the vendor.
 */
import { recoverTypedDataAddress, type Address } from "viem";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import * as dotenv from "dotenv";
import {
  AssetRegistryAbi,
  VendorRegistryAbi,
  MigrationRegistryAbi,
  AuditRegistryAbi,
} from "../lib/abis.js";
import { CHAIN_ID, isValidAddress, isValidBytes32 } from "../config.js";
import { getPublicClient, getWalletClient as getPooledWalletClient } from "./rpc-pool.js";

dotenv.config();

const RELAYER_KEY = process.env.QTRUST_RELAYER_PRIVATE_KEY;
const ASSET_REGISTRY = process.env.QTRUST_ASSET_REGISTRY_ADDRESS as Address;
const VENDOR_REGISTRY = process.env.QTRUST_VENDOR_REGISTRY_ADDRESS as Address;
const MIGRATION_REGISTRY = process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS as Address;
const AUDIT_REGISTRY = process.env.QTRUST_AUDIT_REGISTRY_ADDRESS as Address;

// ------------------------------------------------------------------
// Nonce serialization (audit H-4: TOCTOU race).
//
// The relay flow reads the signer's on-chain nonce and then broadcasts.
// Two concurrent requests signed with the same nonce both pass the read
// check; one transaction reverts on-chain and gas is wasted. Serializing
// check+broadcast per (registry, signer) closes the race in-process.
// ------------------------------------------------------------------
const nonceLocks = new Map<string, Promise<unknown>>();

function withNonceLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = nonceLocks.get(key) ?? Promise.resolve();
  // Chain after the previous holder; a prior failure must not abort
  // subsequent queued operations.
  const run = prev.then(fn, fn);
  const tail = run.catch(() => undefined);
  nonceLocks.set(key, tail);
  void tail.then(() => {
    if (nonceLocks.get(key) === tail) nonceLocks.delete(key);
  });
  return run;
}

// Fail fast in production: a relayer key is mandatory at boot.
if (process.env.NODE_ENV === "production" && !RELAYER_KEY) {
  throw new Error("QTRUST_RELAYER_PRIVATE_KEY is required");
}

let cachedAccount: PrivateKeyAccount | null = null;

/** Lazily load the relayer account. In dev, throws on first use if unset. */
function getRelayerAccount(): PrivateKeyAccount {
  if (!RELAYER_KEY) {
    throw new Error(
      "QTRUST_RELAYER_PRIVATE_KEY is required for transaction signing — refusing to fall back to the deployer key",
    );
  }
  cachedAccount ??= privateKeyToAccount(RELAYER_KEY as `0x${string}`);
  return cachedAccount;
}

function getWalletClient() {
  return getPooledWalletClient(getRelayerAccount());
}

const publicClient = getPublicClient();

export function relayerAddress(): Address {
  return getRelayerAccount().address;
}

export interface RegisterCBOMPayload {
  cbomHash: string;
  metadataURI: string;
}

export async function registerCBOM(payload: RegisterCBOMPayload) {
  const txHash = await getWalletClient().writeContract({
    address: ASSET_REGISTRY,
    abi: AssetRegistryAbi,
    functionName: "registerCBOM",
    args: [payload.cbomHash as `0x${string}`, payload.metadataURI],
  });
  return { txHash };
}

export interface AttestProductPayload {
  productId: string;
  version: string;
  algorithm: string;
  supported: boolean;
  evidenceURI: string;
}

export async function attestProduct(payload: AttestProductPayload) {
  const txHash = await getWalletClient().writeContract({
    address: VENDOR_REGISTRY,
    abi: VendorRegistryAbi,
    functionName: "attestProduct",
    args: [
      payload.productId,
      payload.version,
      payload.algorithm,
      payload.supported,
      payload.evidenceURI,
    ],
  });
  return { txHash };
}

export interface MigrationPayload {
  migrationId: string;
  assetId: string;
  fromAlgorithm: string;
  toAlgorithm: string;
  evidenceHash: string;
  evidenceURI: string;
}

export async function recordMigration(payload: MigrationPayload) {
  const txHash = await getWalletClient().writeContract({
    address: MIGRATION_REGISTRY,
    abi: MigrationRegistryAbi,
    functionName: "recordMigration",
    args: [
      payload.migrationId as `0x${string}`,
      payload.assetId as `0x${string}`,
      payload.fromAlgorithm,
      payload.toAlgorithm,
      payload.evidenceHash as `0x${string}`,
      payload.evidenceURI,
    ],
  });
  return { txHash };
}

// ------------------------------------------------------------------
// EIP-712 gasless attestations
// ------------------------------------------------------------------
export interface SignedAttestationPayload {
  productId: string;
  version: string;
  algorithm: string;
  supported: boolean;
  evidenceURI: string;
  nonce: number;
  signature: string; // 0x-prefixed hex
}

export const EIP712_DOMAIN = {
  name: "QTrustVendorRegistry",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: VENDOR_REGISTRY as Address,
};

export const EIP712_TYPES = {
  ProductAttestation: [
    { name: "productId", type: "string" },
    { name: "version", type: "string" },
    { name: "algorithm", type: "string" },
    { name: "supported", type: "bool" },
    { name: "evidenceURI", type: "string" },
    { name: "nonce", type: "uint256" },
  ],
};

export interface RelayResult {
  txHash: string;
  vendorDid: string;
  attestationId: string;
}

/**
 * Verify a vendor's EIP-712 signature and submit the attestation via the
 * relayer. The on-chain attestation records the SIGNER as the vendor.
 */
export async function relaySignedAttestation(
  payload: SignedAttestationPayload,
): Promise<RelayResult> {
  const message = {
    productId: payload.productId,
    version: payload.version,
    algorithm: payload.algorithm,
    supported: payload.supported,
    evidenceURI: payload.evidenceURI,
    nonce: payload.nonce,
  };

  // Recover the signer from the typed-data signature. Throws on bad
  // signatures — invalid sigs never reach the chain.
  let signer: Address;
  try {
    signer = await recoverTypedDataAddress({
      domain: EIP712_DOMAIN,
      types: EIP712_TYPES,
      primaryType: "ProductAttestation",
      message,
      signature: payload.signature as `0x${string}`,
    });
  } catch {
    throw new Error("EIP-712 signature verification failed: invalid signature");
  }

  // The vendor's current on-chain nonce must match the one they signed.
  // Check + broadcast are serialized per signer (audit H-4: TOCTOU race —
  // two concurrent same-nonce requests would otherwise both pass the read
  // and one transaction would revert on-chain, wasting gas).
  return withNonceLock(`vendor:${signer}`, async () => {
    const onChainNonce = await publicClient.readContract({
      address: VENDOR_REGISTRY,
      abi: VendorRegistryAbi,
      functionName: "nonces",
      args: [signer],
    });
    if (BigInt(onChainNonce) !== BigInt(payload.nonce)) {
      throw new Error(
        `Nonce mismatch: signed ${payload.nonce}, on-chain ${onChainNonce} — signature is stale or replayed`,
      );
    }

    const txHash = await getWalletClient().writeContract({
      address: VENDOR_REGISTRY,
      abi: VendorRegistryAbi,
      functionName: "attestProductSigned",
      args: [
        payload.productId,
        payload.version,
        payload.algorithm,
        payload.supported,
        payload.evidenceURI,
        BigInt(payload.nonce),
        payload.signature as `0x${string}`,
      ],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash, timeout: 120_000 });
    const productAttestedLog = receipt.logs.find(
      (log) => (log as any).eventName === "ProductAttested",
    );
    const attestationId = productAttestedLog && "args" in productAttestedLog
      ? (productAttestedLog.args as Record<string, unknown>)?.attestationId as string | undefined
      : undefined;

    return { txHash, vendorDid: signer, attestationId: attestationId ?? "" };
  });
}

/** Fetch a vendor's current EIP-712 nonce (for signing). */
export async function getVendorNonce(vendor: Address): Promise<bigint> {
  const nonce = await publicClient.readContract({
    address: VENDOR_REGISTRY,
    abi: VendorRegistryAbi,
    functionName: "nonces",
    args: [vendor],
  });
  return BigInt(nonce as bigint | number | string);
}

// ------------------------------------------------------------------
// EIP-712 gasless CBOM registration
// ------------------------------------------------------------------
export const EIP712_ASSET_DOMAIN = {
  name: "QTrustAssetRegistry",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: ASSET_REGISTRY as Address,
};

export const EIP712_CBOM_TYPES = {
  CBOMRegistration: [
    { name: "cbomHash", type: "bytes32" },
    { name: "metadataURI", type: "string" },
    { name: "nonce", type: "uint256" },
  ],
};

export interface SignedCBOMRegistrationPayload {
  cbomHash: string;
  metadataURI: string;
  nonce: number;
  signature: string;
}

export interface RelayCBOMResult {
  txHash: string;
  orgDid: string;
  assetId: string;
}

/**
 * Verify an org's EIP-712 signature and submit the CBOM registration via the
 * relayer. The on-chain registration records the SIGNER as the org.
 */
export async function relaySignedCBOMRegistration(
  payload: SignedCBOMRegistrationPayload,
): Promise<RelayCBOMResult> {
  const message = {
    cbomHash: payload.cbomHash as `0x${string}`,
    metadataURI: payload.metadataURI,
    nonce: payload.nonce,
  };

  let signer: Address;
  try {
    signer = await recoverTypedDataAddress({
      domain: EIP712_ASSET_DOMAIN,
      types: EIP712_CBOM_TYPES,
      primaryType: "CBOMRegistration",
      message,
      signature: payload.signature as `0x${string}`,
    });
  } catch {
    throw new Error("EIP-712 signature verification failed: invalid signature");
  }

  // Check + broadcast serialized per signer (audit H-4: TOCTOU race fix).
  return withNonceLock(`asset:${signer}`, async () => {
    const onChainNonce = await publicClient.readContract({
      address: ASSET_REGISTRY,
      abi: AssetRegistryAbi,
      functionName: "nonces",
      args: [signer],
    });
    if (BigInt(onChainNonce) !== BigInt(payload.nonce)) {
      throw new Error(
        `Nonce mismatch: signed ${payload.nonce}, on-chain ${onChainNonce}`,
      );
    }

    const txHash = await getWalletClient().writeContract({
      address: ASSET_REGISTRY,
      abi: AssetRegistryAbi,
      functionName: "registerCBOMSigned",
      args: [
        payload.cbomHash as `0x${string}`,
        payload.metadataURI,
        BigInt(payload.nonce),
        payload.signature as `0x${string}`,
      ],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash, timeout: 120_000 });
    const cbomRegisteredLog = receipt.logs.find(
      (log) => (log as any).eventName === "CBOMRegistered",
    );
    const assetId = cbomRegisteredLog && "args" in cbomRegisteredLog
      ? (cbomRegisteredLog.args as Record<string, unknown>)?.assetId as string | undefined
      : undefined;

    return { txHash, orgDid: signer, assetId: assetId ?? "" };
  });
}

/** Fetch an org's current EIP-712 nonce for CBOM registration. */
export async function getOrgNonce(org: Address): Promise<bigint> {
  const nonce = await publicClient.readContract({
    address: ASSET_REGISTRY,
    abi: AssetRegistryAbi,
    functionName: "nonces",
    args: [org],
  });
  return BigInt(nonce as bigint | number | string);
}

// ------------------------------------------------------------------
// EIP-712 gasless migration recording
// ------------------------------------------------------------------
export const EIP712_MIGRATION_DOMAIN = {
  name: "QTrustMigrationRegistry",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: MIGRATION_REGISTRY as Address,
};

export const EIP712_MIGRATION_TYPES = {
  MigrationRecording: [
    { name: "migrationId", type: "bytes32" },
    { name: "assetId", type: "bytes32" },
    { name: "fromAlgorithm", type: "string" },
    { name: "toAlgorithm", type: "string" },
    { name: "evidenceHash", type: "bytes32" },
    { name: "evidenceURI", type: "string" },
    { name: "nonce", type: "uint256" },
  ],
};

export interface SignedMigrationPayload {
  migrationId: string;
  assetId: string;
  fromAlgorithm: string;
  toAlgorithm: string;
  evidenceHash: string;
  evidenceURI: string;
  nonce: number;
  signature: string;
}

export interface RelayMigrationResult {
  txHash: string;
  orgDid: string;
  migrationId: string;
}

/**
 * Verify an org's EIP-712 signature and submit the migration recording via the
 * relayer. The on-chain migration records the SIGNER as the org.
 */
export async function relaySignedMigration(
  payload: SignedMigrationPayload,
): Promise<RelayMigrationResult> {
  const message = {
    migrationId: payload.migrationId as `0x${string}`,
    assetId: payload.assetId as `0x${string}`,
    fromAlgorithm: payload.fromAlgorithm,
    toAlgorithm: payload.toAlgorithm,
    evidenceHash: payload.evidenceHash as `0x${string}`,
    evidenceURI: payload.evidenceURI,
    nonce: payload.nonce,
  };

  let signer: Address;
  try {
    signer = await recoverTypedDataAddress({
      domain: EIP712_MIGRATION_DOMAIN,
      types: EIP712_MIGRATION_TYPES,
      primaryType: "MigrationRecording",
      message,
      signature: payload.signature as `0x${string}`,
    });
  } catch {
    throw new Error("EIP-712 signature verification failed: invalid signature");
  }

  // Check + broadcast serialized per signer (audit H-4: TOCTOU race fix).
  return withNonceLock(`migration:${signer}`, async () => {
    const onChainNonce = await publicClient.readContract({
      address: MIGRATION_REGISTRY,
      abi: MigrationRegistryAbi,
      functionName: "nonces",
      args: [signer],
    });
    if (BigInt(onChainNonce) !== BigInt(payload.nonce)) {
      throw new Error(
        `Nonce mismatch: signed ${payload.nonce}, on-chain ${onChainNonce}`,
      );
    }

    const txHash = await getWalletClient().writeContract({
      address: MIGRATION_REGISTRY,
      abi: MigrationRegistryAbi,
      functionName: "recordMigrationSigned",
      args: [
        payload.migrationId as `0x${string}`,
        payload.assetId as `0x${string}`,
        payload.fromAlgorithm,
        payload.toAlgorithm,
        payload.evidenceHash as `0x${string}`,
        payload.evidenceURI,
        BigInt(payload.nonce),
        payload.signature as `0x${string}`,
      ],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash, timeout: 120_000 });
    const migrationRecordedLog = receipt.logs.find(
      (log) => (log as any).eventName === "MigrationRecorded",
    );
    const migrationId = migrationRecordedLog && "args" in migrationRecordedLog ? (migrationRecordedLog.args as Record<string, unknown>)?.migrationId as string | undefined : undefined;

    return { txHash, orgDid: signer, migrationId: migrationId ?? "" };
  });
}

// ------------------------------------------------------------------
// EIP-712 gasless audit posting
// ------------------------------------------------------------------
export const EIP712_AUDIT_DOMAIN = {
  name: "QTrustAuditRegistry",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: AUDIT_REGISTRY as Address,
};

export const EIP712_AUDIT_TYPES = {
  Audit: [
    { name: "orgDid", type: "address" },
    { name: "result", type: "uint8" },
    { name: "assetsReviewed", type: "uint256" },
    { name: "assetsMigrated", type: "uint256" },
    { name: "reportHash", type: "bytes32" },
    { name: "reportURI", type: "string" },
    { name: "nonce", type: "uint256" },
  ],
};

export interface SignedAuditPayload {
  orgDid: string;
  result: number; // AuditRegistry.AuditResult enum (0 Pending, 1 Passed, 2 Failed, 3 Conditional)
  assetsReviewed: number;
  assetsMigrated: number;
  reportHash: string; // 0x-prefixed bytes32
  reportURI: string;
  nonce: number;
  signature: string;
}

export interface RelayAuditResult {
  txHash: string;
  auditorDid: string;
  orgDid: string;
  auditId: string;
}

/**
 * Verify an auditor's EIP-712 signature and submit the audit attestation via
 * the relayer. The signer must hold AUDITOR_ROLE on-chain (checked by the
 * contract); the recorded auditorDid is the SIGNER.
 */
export async function relaySignedAudit(
  payload: SignedAuditPayload,
): Promise<RelayAuditResult> {
  if (!isValidBytes32(payload.reportHash)) {
    throw new Error("reportHash must be a 0x-prefixed 66-char hex string");
  }
  if (!isValidAddress(payload.orgDid)) {
    throw new Error("orgDid must be a valid address");
  }
  const message = {
    orgDid: payload.orgDid as Address,
    result: payload.result,
    assetsReviewed: payload.assetsReviewed,
    assetsMigrated: payload.assetsMigrated,
    reportHash: payload.reportHash as `0x${string}`,
    reportURI: payload.reportURI,
    nonce: payload.nonce,
  };

  let signer: Address;
  try {
    signer = await recoverTypedDataAddress({
      domain: EIP712_AUDIT_DOMAIN,
      types: EIP712_AUDIT_TYPES,
      primaryType: "Audit",
      message,
      signature: payload.signature as `0x${string}`,
    });
  } catch {
    throw new Error("EIP-712 signature verification failed: invalid signature");
  }

  // Check + broadcast serialized per signer (audit H-4: TOCTOU race fix).
  return withNonceLock(`audit:${signer}`, async () => {
    const onChainNonce = await publicClient.readContract({
      address: AUDIT_REGISTRY,
      abi: AuditRegistryAbi,
      functionName: "nonces",
      args: [signer],
    });
    if (BigInt(onChainNonce) !== BigInt(payload.nonce)) {
      throw new Error(
        `Nonce mismatch: signed ${payload.nonce}, on-chain ${onChainNonce}`,
      );
    }

    const txHash = await getWalletClient().writeContract({
      address: AUDIT_REGISTRY,
      abi: AuditRegistryAbi,
      functionName: "postAuditSigned",
      args: [
        payload.orgDid as Address,
        payload.result,
        BigInt(payload.assetsReviewed),
        BigInt(payload.assetsMigrated),
        payload.reportHash as `0x${string}`,
        payload.reportURI,
        BigInt(payload.nonce),
        payload.signature as `0x${string}`,
      ],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash, timeout: 120_000 });
    const auditPostedLog = receipt.logs.find(
      (log) => (log as any).eventName === "AuditPosted",
    );
    const auditId = auditPostedLog && "args" in auditPostedLog
      ? (auditPostedLog.args as Record<string, unknown>)?.auditId as string | undefined
      : undefined;

    return { txHash, auditorDid: signer, orgDid: payload.orgDid, auditId: auditId ?? "" };
  });
}

/** Fetch an auditor's current EIP-712 nonce for audit posting. */
export async function getAuditNonce(auditor: Address): Promise<bigint> {
  const nonce = await publicClient.readContract({
    address: AUDIT_REGISTRY,
    abi: AuditRegistryAbi,
    functionName: "nonces",
    args: [auditor],
  });
  return BigInt(nonce as bigint | number | string);
}