/**
 * Tests for lib/config.ts — contract address resolution and chain
 * derivation (Base Sepolia default, Base mainnet when QTRUST_USE_MAINNET).
 *
 * config.ts reads process.env at module load, so each case resets the module
 * registry and imports a fresh instance after setting the environment.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

const MAINNET_CHAIN_ID = 8453;
const SEPOLIA_CHAIN_ID = 84532;

function withEnv(env: Record<string, string | undefined>, fn: () => Promise<void>): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(env)) {
    saved[key] = process.env[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  return fn().finally(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  });
}

afterEach(() => {
  vi.resetModules();
  delete process.env.QTRUST_USE_MAINNET;
});

describe("config chain derivation", () => {
  it("defaults to Base Sepolia when QTRUST_USE_MAINNET is unset", async () => {
    await withEnv({ QTRUST_USE_MAINNET: undefined }, async () => {
      vi.resetModules();
      const { CHAIN } = await import("@/lib/config");
      expect(CHAIN.id).toBe(SEPOLIA_CHAIN_ID);
      expect(CHAIN.name).toBe("Base Sepolia");
    });
  });

  it("uses Base mainnet when QTRUST_USE_MAINNET=true", async () => {
    await withEnv({ QTRUST_USE_MAINNET: "true" }, async () => {
      vi.resetModules();
      const { CHAIN } = await import("@/lib/config");
      expect(CHAIN.id).toBe(MAINNET_CHAIN_ID);
      expect(CHAIN.name).toBe("Base");
    });
  });

  it("stays on Base Sepolia for any other QTRUST_USE_MAINNET value", async () => {
    await withEnv({ QTRUST_USE_MAINNET: "false" }, async () => {
      vi.resetModules();
      const { CHAIN } = await import("@/lib/config");
      expect(CHAIN.id).toBe(SEPOLIA_CHAIN_ID);
    });
  });

  it("honors QTRUST_BASE_SEPOLIA_RPC for the mainnet RPC override", async () => {
    await withEnv(
      { QTRUST_USE_MAINNET: "true", QTRUST_BASE_SEPOLIA_RPC: "https://rpc.example.test" },
      async () => {
        vi.resetModules();
        const { CHAIN } = await import("@/lib/config");
        expect(CHAIN.rpcUrls.default.http).toEqual(["https://rpc.example.test"]);
      },
    );
  });
});

describe("config contract address resolution", () => {
  it("falls back to 0x0 when no addresses are configured", async () => {
    await withEnv(
      {
        QTRUST_VENDOR_REGISTRY_ADDRESS: undefined,
        QTRUST_ASSET_REGISTRY_ADDRESS: undefined,
        QTRUST_MIGRATION_REGISTRY_ADDRESS: undefined,
        QTRUST_AUDIT_REGISTRY_ADDRESS: undefined,
        QTRUST_REGISTRY_ADDRESS: undefined,
      },
      async () => {
        vi.resetModules();
        const { CONTRACTS } = await import("@/lib/config");
        expect(CONTRACTS.vendorRegistry).toBe("0x0");
        expect(CONTRACTS.assetRegistry).toBe("0x0");
      },
    );
  });

  it("resolves the vendor registry from QTRUST_VENDOR_REGISTRY_ADDRESS", async () => {
    const address = "0x1234567890abcdef1234567890abcdef12345678";
    await withEnv({ QTRUST_VENDOR_REGISTRY_ADDRESS: address }, async () => {
      vi.resetModules();
      const { CONTRACTS } = await import("@/lib/config");
      expect(CONTRACTS.vendorRegistry).toBe(address);
    });
  });

  it("prefers QTRUST_ASSET_REGISTRY_ADDRESS over the legacy QTRUST_REGISTRY_ADDRESS", async () => {
    await withEnv(
      {
        QTRUST_ASSET_REGISTRY_ADDRESS: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        QTRUST_REGISTRY_ADDRESS: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      },
      async () => {
        vi.resetModules();
        const { CONTRACTS } = await import("@/lib/config");
        expect(CONTRACTS.assetRegistry).toBe("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      },
    );
  });

  it("uses the legacy QTRUST_REGISTRY_ADDRESS as asset registry fallback", async () => {
    await withEnv(
      {
        QTRUST_ASSET_REGISTRY_ADDRESS: undefined,
        QTRUST_REGISTRY_ADDRESS: "0xcccccccccccccccccccccccccccccccccccccccc",
      },
      async () => {
        vi.resetModules();
        const { CONTRACTS } = await import("@/lib/config");
        expect(CONTRACTS.assetRegistry).toBe("0xcccccccccccccccccccccccccccccccccccccccc");
      },
    );
  });
});

describe("parseAssetId / toBytes32", () => {
  it("accepts well-formed bytes32 asset IDs", async () => {
    vi.resetModules();
    const { parseAssetId } = await import("@/lib/config");
    const id = `0x${"ab".repeat(32)}`;
    expect(parseAssetId(id)).toBe(id);
  });

  it("rejects non-0x-prefixed and wrong-length asset IDs", async () => {
    vi.resetModules();
    const { parseAssetId } = await import("@/lib/config");
    expect(() => parseAssetId("no-hex-prefix")).toThrow(/0x-prefixed/);
    expect(() => parseAssetId(`0x${"ab".repeat(31)}`)).toThrow(/32 bytes/);
  });

  it("pads short hashes to bytes32", async () => {
    vi.resetModules();
    const { toBytes32 } = await import("@/lib/config");
    expect(toBytes32("0xdead")).toBe(`0x${"0".repeat(60)}dead`);
  });
});
