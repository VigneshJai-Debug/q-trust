import { describe, it, expect } from "vitest";
import { sanitizeUri } from "../sanitize-uri";

describe("sanitizeUri", () => {
  it("allows https", () => {
    expect(sanitizeUri("https://example.com/report.pdf")).toBe(
      "https://example.com/report.pdf"
    );
  });

  it("allows http and ipfs schemes", () => {
    expect(sanitizeUri("http://example.com/a")).toBe("http://example.com/a");
    expect(sanitizeUri("ipfs://QmHash")).toBe("ipfs://QmHash");
    expect(sanitizeUri("ipns://example.com")).toBe("ipns://example.com");
  });

  it.each(["javascript:alert(1)", "data:text/html,<script>", "vbscript:x", "file:///etc/passwd"])(
    "blocks %s",
    (uri) => {
      expect(sanitizeUri(uri)).toBeNull();
    }
  );

  it("blocks URIs with embedded credentials", () => {
    expect(sanitizeUri("https://evil.com@good.example.com")).toBeNull();
  });

  it("returns null for garbage input", () => {
    expect(sanitizeUri(null)).toBeNull();
    expect(sanitizeUri(undefined)).toBeNull();
    expect(sanitizeUri("")).toBeNull();
    expect(sanitizeUri("not a url at all")).toBeNull();
  });
});
