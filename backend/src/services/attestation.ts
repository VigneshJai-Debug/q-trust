/**
 * Relayer service — writes attestations to the Q-Trust contracts with the
 * configured relayer account (QTRUST_RELAYER_PRIVATE_KEY, falling back to
 * QTRUST_DEPLOYER_PRIVATE_KEY).
 *
 * Also implements EIP-712 gasless attestations: vendors sign typed data
 * off-chain (SDK sign_attestation / MetaMask); the relayer verifies the
 * signature, recovers the signer, and submits it — vendors never need to
 * hold funds or run a node. The contract records the SIGNER as the vendor.
 */
import { createPublicClient, createWalletClient, http, recoverTypedDataAddress, type Address } from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import * as dotenv from "dotenv";
import {
  AssetRegistryAbi,
  VendorRegistryAbi,
  MigrationRegistryAbi,
} from "../lib/abis.js";

dotenv.config();

const RELAYER_KEY = process.env.QTRUST_RELAYER_PRIVATE_KEY || process.env.QTRUST_DEPLOYER_PRIVATE_KEY!;
const RPC_URL = process.env.QTRUST_BASE_SEPOLIA_RPC ?? "http://127.0.0.1:8545";
const ASSET_REGISTRY = process.env.QTRUST_ASSET_REGISTRY_ADDRESS as Address;
const VENDOR_REGISTRY = process.env.QTRUST_VENDOR_REGISTRY_ADDRESS as Address;
const MIGRATION_REGISTRY = process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS as Address;

if (!RELAYER_KEY) {
  throw new Error("QTRUST_RELAYER_PRIVATE_KEY or QTRUST_DEPLOYER_PRIVATE_KEY is required");
}

const account = privateKeyToAccount(RELAYER_KEY as `0x${string}`);
const walletClient = createWalletClient({
  account,
  chain: baseSepolia,
  transport: http(RPC_URL),
});
const publicClient = createPublicClient({
  chain: baseSepolia,
  transport: http(RPC_URL),
});

export const relayerAddress = account.address;

export interface RegisterCBOMPayload {
  cbomHash: string;
  metadataURI: string;
}

export async function registerCBOM(payload: RegisterCBOMPayload) {
  const txHash = await walletClient.writeContract({
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
  const txHash = await walletClient.writeContract({
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
  const txHash = await walletClient.writeContract({
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
  chainId: 84532,
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

  const txHash = await walletClient.writeContract({
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

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  const productAttestedLog = (receipt.logs as any[]).find(
    (log: any) => log.eventName === "ProductAttested",
  );
  const attestationId = productAttestedLog?.args?.attestationId as string | undefined;

  return { txHash, vendorDid: signer, attestationId: attestationId ?? "" };
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