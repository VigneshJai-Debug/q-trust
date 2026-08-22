import { describe, it, expect } from "vitest";
import { parseAssetId, toBytes32 } from "../src/config.js";

describe("parseAssetId", () => {
  it("accepts valid 0x-prefixed 66-char hex", () => {
    const valid = "0x" + "ab".repeat(32);
    expect(parseAssetId(valid)).toBe(valid);
  });

  it("rejects non-hex prefix", () => {
    expect(() => parseAssetId("1234" + "ab".repeat(31))).toThrow("0x-prefixed hex");
  });

  it("rejects wrong length", () => {
    expect(() => parseAssetId("0x" + "ab".repeat(16))).toThrow("32 bytes");
  });
});

describe("toBytes32", () => {
  it("pads short hex to bytes32", () => {
    const result = toBytes32("0x1234");
    expect(result).toBe("0x" + "00".repeat(30) + "1234");
    expect(result.length).toBe(66);
  });

  it("truncates long hex to bytes32", () => {
    const result = toBytes32("0x" + "ab".repeat(40));
    expect(result.length).toBe(66);
  });

  it("rejects non-hex prefix", () => {
    expect(() => toBytes32("1234")).toThrow("0x");
  });
});
