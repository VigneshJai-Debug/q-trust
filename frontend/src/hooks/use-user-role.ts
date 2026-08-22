"use client";

/**
 * Role-based access control hook for the Q-Trust frontend.
 *
 * Checks the connected wallet address against on-chain registries to determine
 * the user's role(s): org, vendor, auditor, or none.
 */
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useWallet } from "@/components/dynamic-provider";
import { fetchOrgAssets, fetchVendorAttestations } from "@/lib/api";

export type UserRole = "org" | "vendor" | "auditor" | "none";

export interface UserRoleInfo {
  role: UserRole;
  isOrg: boolean;
  isVendor: boolean;
  isAuditor: boolean;
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

  return useMemo(() => {
    if (walletLoading || !address) {
      return { role: "none", isOrg: false, isVendor: false, isAuditor: false, isLoading: walletLoading };
    }

    const orgData = orgAssets.data;
    const vendorData = vendorAttestations.data;
    const isOrg = Boolean(orgData && "total" in orgData && orgData.total > 0);
    const isVendor = Boolean(vendorData && "attestations" in vendorData && vendorData.attestations.length > 0);

    let role: UserRole = "none";
    if (isOrg) role = "org";
    else if (isVendor) role = "vendor";

    return {
      role,
      isOrg,
      isVendor,
      isAuditor: false,
      isLoading: orgAssets.isLoading || vendorAttestations.isLoading,
    };
  }, [address, walletLoading, orgAssets.data, vendorAttestations.data, orgAssets.isLoading, vendorAttestations.isLoading]);
}
