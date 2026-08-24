"use client";

/**
 * Role-based access control hook for the Q-Trust frontend.
 *
 * The role is strictly a UI hint used to tailor what the current wallet sees.
 * It must never be treated as authorization; admin controls are only rendered
 * when role === "admin" (via isPrivileged). Real authorization happens
 * server-side / on-chain.
 *
 * Detection:
 *   - org:    address has registered assets (backend read model)
 *   - vendor: address has issued attestations (backend read model)
 *   - admin:  address holds DEFAULT_ADMIN_ROLE (bytes32 zero) on VendorRegistry,
 *             read on-chain via the wagmi public client. Runs alongside the
 *             org/vendor queries and takes precedence, since admins act across
 *             registries regardless of their own assets or attestations.
 */
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAccount, usePublicClient } from "wagmi";
import type { Address } from "viem";
import { fetchOrgAssets, fetchVendorAttestations } from "@/lib/api";
import { CONTRACTS } from "@/lib/config";

export type UserRole = "org" | "vendor" | "auditor" | "admin" | "none";

export interface UserRoleInfo {
  role: UserRole;
  isOrg: boolean;
  isVendor: boolean;
  isAuditor: boolean;
  isPrivileged: boolean;
  isLoading: boolean;
}

/** OpenZeppelin AccessControl DEFAULT_ADMIN_ROLE — bytes32(0). */
export const DEFAULT_ADMIN_ROLE =
  "0x0000000000000000000000000000000000000000000000000000000000000000" as const;

const VENDOR_REGISTRY_ABI = [
  {
    inputs: [
      { name: "role", type: "bytes32" },
      { name: "account", type: "address" },
    ],
    name: "hasRole",
    outputs: [{ internalType: "bool", name: "", type: "bool" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

export function isAdminRole(candidate: UserRole): boolean {
  return candidate === "admin";
}

async function hasDefaultAdminRole(
  client: ReturnType<typeof usePublicClient>,
  address: Address,
): Promise<boolean> {
  const registry = CONTRACTS.vendorRegistry;
  if (!client || !registry || registry === "0x0") {
    return false;
  }
  try {
    return await client.readContract({
      address: registry,
      abi: VENDOR_REGISTRY_ABI,
      functionName: "hasRole",
      args: [DEFAULT_ADMIN_ROLE, address],
    });
  } catch {
    return false;
  }
}

export function useUserRole(): UserRoleInfo {
  const { address, isConnecting, isReconnecting } = useAccount();
  const publicClient = usePublicClient();
  const walletLoading = isConnecting || isReconnecting;

  const orgAssets = useQuery({
    queryKey: ["org-assets", address],
    queryFn: () => fetchOrgAssets(address!),
    enabled: Boolean(address),
    staleTime: 60_000,
    retry: false,
  });

  const vendorAttestations = useQuery({
    queryKey: ["vendor-attestations", address],
    queryFn: () => fetchVendorAttestations(address!),
    enabled: Boolean(address),
    staleTime: 60_000,
    retry: false,
  });

  const adminRole = useQuery({
    queryKey: ["admin-role", address],
    queryFn: () => hasDefaultAdminRole(publicClient, address!),
    enabled: Boolean(address),
    staleTime: 60_000,
    retry: false,
  });

  return useMemo(() => {
    if (walletLoading || !address) {
      return { role: "none" as const, isOrg: false, isVendor: false, isAuditor: false, isPrivileged: false, isLoading: walletLoading };
    }

    const orgData = orgAssets.data;
    const vendorData = vendorAttestations.data;
    const orgTotal =
      orgData && typeof orgData === "object" && "total" in orgData
        ? Number((orgData as { total?: unknown }).total)
        : 0;
    const isOrg = Number.isFinite(orgTotal) && orgTotal > 0;
    const isVendor = Boolean(vendorData && "attestations" in vendorData && vendorData.attestations.length > 0);

    let role: UserRole = "none";
    if (isOrg) role = "org";
    else if (isVendor) role = "vendor";
    if (adminRole.data === true) role = "admin";

    return {
      role,
      isOrg,
      isVendor,
      isAuditor: false,
      isPrivileged: isAdminRole(role),
      isLoading: orgAssets.isLoading || vendorAttestations.isLoading || adminRole.isLoading,
    };
  }, [address, walletLoading, orgAssets.data, vendorAttestations.data, orgAssets.isLoading, vendorAttestations.isLoading, adminRole.data, adminRole.isLoading]);
}
