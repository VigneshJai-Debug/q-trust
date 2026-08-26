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
 *
 * Build-time guard (audit F-2): in production the env var must be set to a
 * real project ID — "demo" or missing is a deployment error and the build
 * must fail fast.
 */
const RAW_WALLETCONNECT_PROJECT_ID = process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID;

// Explicit validation: undefined or "demo" is never valid in production.
if (!RAW_WALLETCONNECT_PROJECT_ID || RAW_WALLETCONNECT_PROJECT_ID === "demo") {
  const msg =
    "[Q-Trust] NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID is not set or is 'demo' — wallet connections will be rate-limited. " +
    "Set a real project ID from https://cloud.walletconnect.com for production.";
  if (process.env.NODE_ENV === "production") {
    throw new Error(msg);
  } else {
    console.warn(msg);
  }
}

const WALLETCONNECT_PROJECT_ID = RAW_WALLETCONNECT_PROJECT_ID ?? "demo";

if (!WALLETCONNECT_PROJECT_ID || typeof WALLETCONNECT_PROJECT_ID !== "string") {
  throw new Error("[Q-Trust] WALLETCONNECT_PROJECT_ID resolved to empty — wagmi config cannot initialize.");
}

export const wagmiConfig = getDefaultConfig({
  appName: "Q-Trust",
  projectId: WALLETCONNECT_PROJECT_ID,
  chains: [base, baseSepolia],
  ssr: true,
});
