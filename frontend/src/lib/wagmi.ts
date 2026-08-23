/**
 * wagmi + RainbowKit wallet configuration.
 *
 * Chains: Base (mainnet) and Base Sepolia — matching the deployments in
 * lib/config.ts. The expected chain for contract interactions is derived
 * from QTRUST_USE_MAINNET there (Base Sepolia default, mainnet when set).
 */
import { getDefaultConfig } from "@rainbow-me/rainbowkit";
import { base, baseSepolia } from "wagmi/chains";

/**
 * WalletConnect project ID. RainbowKit requires a non-empty string; a
 * placeholder keeps dev builds working, but real wallet connections need a
 * valid project ID from https://cloud.walletconnect.com.
 */
const WALLETCONNECT_PROJECT_ID =
  process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID ?? "demo";

export const wagmiConfig = getDefaultConfig({
  appName: "Q-Trust",
  projectId: WALLETCONNECT_PROJECT_ID,
  chains: [base, baseSepolia],
  ssr: true,
});
