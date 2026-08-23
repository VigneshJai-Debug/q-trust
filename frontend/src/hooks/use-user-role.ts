"use client";

/**
 * Role-based access control hook for the Q-Trust frontend.
 *
 * The role is strictly a UI hint used to tailor what the current wallet sees.
 * It must never be treated as authorization; admin controls are only rendered
 * when role === "admin" (via isPrivileged). Real authorization happens
 * server-side / on-chain.
 */
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useWallet } from "@/components/dynamic-provider";
import { fetchOrgAssets, fetchVendorAttestations } from "@/lib/api";

export type UserRole = "org" | "vendor" | "auditor" | "admin" | "none";

export interface UserRoleInfo {
  role: UserRole;
  isOrg: boolean;
  isVendor: boolean;
  isAuditor: boolean;
  isPrivileged: boolean;
  isLoading: boolean;
}

export function useUserRole(): UserRoleInfo {
  const { user, loading: walletLoading } = useWallet();
  const address = user?.isAuthenticated ? user.address : null;

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

  function isAdminRole(candidate: UserRole): boolean {
    return candidate === "admin";
  }

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

    return {
      role,
      isOrg,
      isVendor,
      isAuditor: false,
      isPrivileged: isAdminRole(role),
      isLoading: orgAssets.isLoading || vendorAttestations.isLoading,
    };
  }, [address, walletLoading, orgAssets.data, vendorAttestations.data, orgAssets.isLoading, vendorAttestations.isLoading]);
}
