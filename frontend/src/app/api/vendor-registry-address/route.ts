import { CONTRACTS } from "@/lib/config";

/**
 * Public endpoint exposing the VendorRegistry address so browser wallets can
 * build the EIP-712 domain. Contract addresses are public by design.
 */
export async function GET() {
  return Response.json({ address: CONTRACTS.vendorRegistry });
}