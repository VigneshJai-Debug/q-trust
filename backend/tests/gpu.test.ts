import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

process.env.NODE_ENV = "test";
process.env.QTRUST_GPU_ENABLED = "true";

const bridgeResponses: Array<{ code: number; stdout: string }> = [];
let capturedArgs: { cmd: string; args: string[]; stdin: string }[] = [];

vi.mock("node:child_process", () => {
  return {
    spawn: vi.fn((_cmd: string, args: string[]) => {
      const response = bridgeResponses.shift() ?? { code: 0, stdout: "{}" };
      const child: any = new EventEmitter();
      (child as any).stdout = new EventEmitter();
      (child as any).stderr = new EventEmitter();
      const stdinWrites: string[] = [];
      (child as any).stdin = {
        write: (s: string) => stdinWrites.push(s),
        end: () => {
          capturedArgs.push({ cmd: _cmd, args, stdin: stdinWrites.join("") });
          process.nextTick(() => {
            (child as any).stdout.emit("data", Buffer.from(response.stdout));
            child.emit("close", response.code);
          });
        },
      };
      return child;
    }),
  };
});

const plannerFetch = vi.fn();
vi.stubGlobal("fetch", plannerFetch);

const { registerGPURoutes } = await import("../src/services/gpu-service.js");

async function build() {
  const { default: Fastify } = await import("fastify");
  const app = Fastify({ logger: false });
  await app.register(registerGPURoutes);
  await app.ready();
  return app;
}

function ok(payload: unknown) {
  return { code: 0, stdout: JSON.stringify(payload) };
}

beforeEach(() => {
  bridgeResponses.length = 0;
  capturedArgs = [];
  plannerFetch.mockReset();
  process.env.QTRUST_GPU_ENABLED = "true";
});

afterEach(() => {
  delete process.env.QTRUST_GPU_ENABLED;
  delete process.env.QTRUST_API_KEYS;
  process.env.QTRUST_GPU_ENABLED = "true";
});

describe("GPU route authentication", () => {
  it("401s when QTRUST_API_KEYS is configured and no key is sent", async () => {
    process.env.QTRUST_API_KEYS = "test-key-1";
    const app = await build();
    const res = await app.inject({ method: "POST", url: "/v1/gpu/side-channel/analyze", payload: {} });
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body)).toEqual({ error: "Invalid or missing API key" });
  });

  it("accepts requests carrying a configured key", async () => {
    process.env.QTRUST_API_KEYS = "test-key-1";
    bridgeResponses.push(ok({ score: 0.1, is_anomalous: false }));
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/anomaly/score",
      headers: { "x-api-key": "test-key-1" },
      payload: { cbom: { assets: [] } },
    });
    expect(res.statusCode).toBe(200);
  });

  it("stays open in local dev when no keys are configured", async () => {
    delete process.env.QTRUST_API_KEYS;
    bridgeResponses.push(ok({ score: 0.1, is_anomalous: false }));
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/anomaly/score",
      payload: { cbom: { assets: [] } },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe("GET /v1/gpu/status", () => {
  it("returns probe result and enabled flag", async () => {
    bridgeResponses.push(ok({ available: true, device_name: "NVIDIA A100", memory_total_gb: 80 }));
    const app = await build();
    const res = await app.inject({ method: "GET", url: "/v1/gpu/status" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      available: true,
      device_name: "NVIDIA A100",
      gpu_enabled: true,
    });
    await app.close();
  });

  it("works even when GPU features are disabled", async () => {
    process.env.QTRUST_GPU_ENABLED = "false";
    bridgeResponses.push(ok({ available: false, device_name: null, memory_total_gb: null }));
    const app = await build();
    const res = await app.inject({ method: "GET", url: "/v1/gpu/status" });
    expect(res.statusCode).toBe(200);
    expect(res.json().gpu_enabled).toBe(false);
    await app.close();
  });
});

describe("GPU gate", () => {
  it("503s analyze/anomaly/quantum when disabled", async () => {
    process.env.QTRUST_GPU_ENABLED = "false";
    const app = await build();
    for (const req of [
      { method: "POST", url: "/v1/gpu/side-channel/analyze", payload: {} },
      { method: "POST", url: "/v1/gpu/anomaly/score", payload: { cbom: { assets: [] } } },
    ] as const) {
      const res = await app.inject({ method: req.method, url: req.url, payload: req.payload });
      expect(res.statusCode).toBe(503);
    }
    const res = await app.inject({ method: "GET", url: "/v1/gpu/quantum/estimate/2048" });
    expect(res.statusCode).toBe(503);
    await app.close();
  });
});

describe("POST /v1/gpu/side-channel/analyze", () => {
  it("passes payload via stdin and returns verdict", async () => {
    bridgeResponses.push(
      ok({
        leakage_probability: 0.02,
        verdict: "SIDE_CHANNEL_VERIFIED",
        evidence_hash: "0x" + "aa".repeat(32),
        traces_collected: 10000,
        gpu_used: true,
      }),
    );
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/side-channel/analyze",
      payload: { simulated: true, leakage_prob: 0.0, n_traces: 10_000 },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().verdict).toBe("SIDE_CHANNEL_VERIFIED");
    const call = capturedArgs[0];
    expect(call.args[1]).toBe("side-channel");
    const sent = JSON.parse(call.stdin);
    expect(sent.simulated).toBe(true);
    expect(sent.leakage_prob).toBe(0.0);
    await app.close();
  });

  it("requires implementation_cmd when simulated=false", async () => {
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/side-channel/analyze",
      payload: { simulated: false },
    });
    expect(res.statusCode).toBe(400);
    await app.close();
  });

  it("409 on untrained detector marker", async () => {
    bridgeResponses.push({ code: 3, stdout: JSON.stringify({ error: "untrained_detector" }) });
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/side-channel/analyze",
      payload: {},
    });
    expect(res.statusCode).toBe(409);
    await app.close();
  });

  it("502 when bridge fails without leaking stderr", async () => {
    bridgeResponses.push({ code: 1, stdout: "" });
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/side-channel/analyze",
      payload: {},
    });
    expect(res.statusCode).toBe(502);
    expect(JSON.parse(res.body)).toEqual({ error: "analysis_failed" });
    await app.close();
  });

  it("rejects out-of-range leakage_prob", async () => {
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/side-channel/analyze",
      payload: { leakage_prob: 1.5 },
    });
    expect(res.statusCode).toBe(400);
    await app.close();
  });
});

describe("POST /v1/gpu/anomaly/score", () => {
  it("scores a cbom", async () => {
    bridgeResponses.push(
      ok({ anomaly_score: 0.42, is_anomalous: false, threshold: 0.5, top_anomalous_assets: [] }),
    );
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/anomaly/score",
      payload: { cbom: { assets: [] } },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().is_anomalous).toBe(false);
    await app.close();
  });

  it("409 on untrained detector", async () => {
    bridgeResponses.push({ code: 3, stdout: JSON.stringify({ error: "untrained_detector" }) });
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/anomaly/score",
      payload: { cbom: { assets: [] } },
    });
    expect(res.statusCode).toBe(409);
    expect(res.json().error).toBe("anomaly_detector_untrained");
    await app.close();
  });

  it("400 when cbom missing", async () => {
    const app = await build();
    const res = await app.inject({ method: "POST", url: "/v1/gpu/anomaly/score", payload: {} });
    expect(res.statusCode).toBe(400);
    await app.close();
  });
});

describe("GET /v1/gpu/quantum/estimate/:bits", () => {
  it("estimates for RSA-2048 with validated params", async () => {
    bridgeResponses.push(
      ok({ rsa_key_size: 2048, logical_qubits_needed: 4099, physical_qubits_needed: 4_099_000 }),
    );
    const app = await build();
    const res = await app.inject({ method: "GET", url: "/v1/gpu/quantum/estimate/2048" });
    expect(res.statusCode).toBe(200);
    expect(res.json().logical_qubits_needed).toBe(4099);
    const sent = JSON.parse(capturedArgs[0].stdin);
    expect(sent.bits).toBe(2048);
    await app.close();
  });

  it("rejects out-of-range bits", async () => {
    const app = await build();
    const res = await app.inject({ method: "GET", url: "/v1/gpu/quantum/estimate/128" });
    expect([400, 503]).toContain(res.statusCode);
    await app.close();
  });
});

describe("POST /v1/gpu/rl/plan", () => {
  it("proxies to the planner microservice", async () => {
    plannerFetch.mockResolvedValue(
      new Response(JSON.stringify({ method: "rl_policy", migration_order: [] }), { status: 200 }),
    );
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/rl/plan",
      payload: { cbom: { assets: [] } },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().method).toBe("rl_policy");
    expect(plannerFetch.mock.calls[0][0]).toContain("/rl/plan");
    await app.close();
  });

  it("503 when planner is down", async () => {
    plannerFetch.mockRejectedValue(new Error("ECONNREFUSED"));
    const app = await build();
    const res = await app.inject({
      method: "POST",
      url: "/v1/gpu/rl/plan",
      payload: { cbom: { assets: [] } },
    });
    expect(res.statusCode).toBe(503);
    await app.close();
  });
});
