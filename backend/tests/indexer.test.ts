import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Audit H-6 regression: the rpc-pool Proxy wraps every viem method in a
 * Promise — including watchEvent, which returns its unwatch function
 * synchronously. Before the fix, watchLive stored a Promise in `unwatchers`
 * and stopIndexer silently failed to unsubscribe. This test asserts that
 * after awaiting watchEvent, stopIndexer invokes the REAL unwatch function.
 */
vi.mock("pg", () => {
  const query = vi.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  class Pool {
    connect = vi.fn().mockResolvedValue({
      query,
      release: vi.fn(),
    });
    query = query;
    end = vi.fn().mockResolvedValue(undefined);
  }
  return { default: { Pool } };
});

const unwatch = vi.fn();
const watchEvent = vi.fn().mockImplementation(() => unwatch);

vi.mock("../src/services/rpc-pool.js", () => ({
  getPublicClient: () => ({
    watchEvent,
    getBlockNumber: vi.fn().mockResolvedValue(1000n),
    getLogs: vi.fn().mockResolvedValue([]),
    getBlock: vi.fn().mockRejectedValue(new Error("no rpc")),
  }),
  getWalletClient: vi.fn(),
}));

vi.mock("../src/lib/abis.js", async (importOriginal) => {
  const orig = await importOriginal<Record<string, unknown>>();
  // Real ABIs keep parseAbiItem-compatible event fragments available.
  return orig;
});

describe("indexer graceful shutdown", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.QTRUST_PG_URL = "postgres://test";
    process.env.QTRUST_ASSET_REGISTRY_ADDRESS =
      "0x1111111111111111111111111111111111111111";
    process.env.QTRUST_VENDOR_REGISTRY_ADDRESS =
      "0x2222222222222222222222222222222222222222";
    process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS =
      "0x3333333333333333333333333333333333333333";
    process.env.QTRUST_AUDIT_REGISTRY_ADDRESS =
      "0x4444444444444444444444444444444444444444";
    process.env.QTRUST_INDEXER_FROM_BLOCK = "0";
    unwatch.mockClear();
    watchEvent.mockClear();
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.resetModules();
  });

  it("stopIndexer awaits the pooled watchEvent and calls the real unwatch", async () => {
    const indexer = await import("../src/services/indexer.js");

    await indexer.startIndexer();

    // watchEvent must have been awaited per event spec (7 specs).
    expect(watchEvent).toHaveBeenCalledTimes(7);
    // The stored value must be a FUNCTION (the actual unwatch), not a Promise.
    expect(unwatch).not.toHaveBeenCalled();

    indexer.stopIndexer();

    expect(unwatch).toHaveBeenCalledTimes(7);
  });

  it("startIndexer is idempotent and does not double-subscribe", async () => {
    const indexer = await import("../src/services/indexer.js");
    await indexer.startIndexer();
    await indexer.startIndexer();
    expect(watchEvent).toHaveBeenCalledTimes(7);
    indexer.stopIndexer();
    expect(unwatch).toHaveBeenCalledTimes(7);
  });
});
