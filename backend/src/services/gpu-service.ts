import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { requireApiKey } from "../middleware/auth.js";
import {
  SideChannelAnalyzeSchema,
  AnomalyScoreSchema,
  RLPlanSchema,
} from "../schemas/index.js";

const GPU_BRIDGE = process.env.QTRUST_GPU_BRIDGE ||
  fileURLToPath(new URL("../../scripts/gpu_bridge.py", import.meta.url));
const PLANNER_URL = process.env.QTRUST_PLANNER_URL ?? "http://127.0.0.1:8000";

const STATUS_CACHE_TTL_MS = 60_000;
let cachedStatus: { at: number; data: GpuStatus } | null = null;

interface GpuStatus {
  available: boolean;
  device_name: string | null;
  memory_total_gb: number | null;
  models_loaded: string[];
}

function gpuEnabled(): boolean {
  return process.env.QTRUST_GPU_ENABLED === "true";
}

interface BridgeResult {
  code: number;
  payload: Record<string, unknown>;
}

/**
 * Run the static python bridge, passing the request payload via stdin only.
 * Request data never touches argv or interpolated source strings.
 */
function runBridge(
  subcommand: string,
  payload: Record<string, unknown>,
  timeoutMs: number,
): Promise<BridgeResult> {
  return new Promise((resolve) => {
    const child = spawn(process.env.QTRUST_INSPECTOR_PYTHON || "python3", [GPU_BRIDGE, subcommand], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);

    child.stdout.on("data", (d: Buffer) => (stdout += d));
    child.stderr.on("data", (d: Buffer) => (stderr += d));
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ code: -1, payload: { error: `bridge_spawn_failed: ${err.message}` } });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(stdout.trim());
      } catch {
        parsed = { error: "bridge_invalid_output" };
      }
      if (stderr.trim()) console.error(`[gpu-bridge] ${subcommand}: ${stderr.trim().slice(0, 500)}`);
      resolve({ code: code ?? -1, payload: parsed });
    });

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

function fail(reply: FastifyReply, code: number, body: Record<string, unknown>) {
  return reply.code(code).send(body);
}

export async function registerGPURoutes(server: FastifyInstance): Promise<void> {
  // Auth gate for every /v1/gpu/* route (audit B-1: side-channel analyze was an
  // unauthenticated RCE when QTRUST_GPU_ENABLED=true).
  server.addHook("preHandler", requireApiKey);
  server.get("/v1/gpu/status", {
    schema: { tags: ["gpu"], summary: "GPU availability and model info" },
    async handler() {
      const now = Date.now();
      if (cachedStatus && now - cachedStatus.at < STATUS_CACHE_TTL_MS) {
        return { ...cachedStatus.data, gpu_enabled: gpuEnabled(), planner_url: PLANNER_URL };
      }
      const { payload } = await runBridge("status", {}, 10_000);
      const data: GpuStatus = {
        available: payload.available === true,
        device_name: (payload.device_name as string) ?? null,
        memory_total_gb: (payload.memory_total_gb as number) ?? null,
        models_loaded: [],
      };
      cachedStatus = { at: now, data };
      return { ...data, gpu_enabled: gpuEnabled(), planner_url: PLANNER_URL };
    },
  });

  server.post("/v1/gpu/side-channel/analyze", {
    schema: {
      tags: ["gpu"],
      summary: "Analyze a PQC implementation for timing side-channel leakage",
      body: SideChannelAnalyzeSchema,
    },
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
    async handler(request: FastifyRequest<{ Body: SideChannelBody }>, reply: FastifyReply) {
      if (!gpuEnabled()) return fail(reply, 503, { error: "GPU features disabled" });
      const b = request.body;
      const payload: Record<string, unknown> = { n_traces: b.n_traces ?? 10_000 };
      if (b.simulated === false) {
        if (!Array.isArray(b.implementation_cmd) || b.implementation_cmd.length === 0) {
          return fail(reply, 400, { error: "implementation_cmd required when simulated=false" });
        }
        payload.simulated = false;
        payload.implementation_cmd = b.implementation_cmd;
      } else {
        payload.simulated = true;
        payload.leakage_prob = b.leakage_prob ?? 0;
      }
      const started = Date.now();
      const { code, payload: result } = await runBridge(
        "side-channel",
        payload,
        b.simulated === false ? 300_000 : 120_000,
      );
      request.log.info({ op: "side_channel", ms: Date.now() - started }, "gpu analysis done");
      if (code === 3) {
        return fail(reply, 409, {
          error: "side_channel_detector_untrained",
          hint: "train via inspector or set QTRUST_SIDE_CHANNEL_MODEL",
        });
      }
      if (code !== 0 || result.error) {
        return fail(reply, 502, { error: "analysis_failed" });
      }
      return result;
    },
  });

  server.post("/v1/gpu/anomaly/score", {
    schema: {
      tags: ["gpu"],
      summary: "Score a CBOM for anomalies (VAE reconstruction error)",
      body: AnomalyScoreSchema,
    },
    config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
    async handler(request: FastifyRequest<{ Body: { cbom: Record<string, unknown> } }>, reply: FastifyReply) {
      if (!gpuEnabled()) return fail(reply, 503, { error: "GPU features disabled" });
      const { code, payload: result } = await runBridge("anomaly", { cbom: request.body.cbom }, 60_000);
      if (code === 3) {
        return fail(reply, 409, {
          error: "anomaly_detector_untrained",
          hint: "train the VAE first or set QTRUST_ANOMALY_MODEL",
        });
      }
      if (code !== 0 || result.error) {
        return fail(reply, 502, { error: "anomaly_scoring_failed" });
      }
      return result;
    },
  });

  server.get("/v1/gpu/quantum/estimate/:bits", {
    schema: {
      tags: ["gpu"],
      summary: "Estimate quantum resources needed to break RSA-n",
      params: {
        type: "object",
        required: ["bits"],
        properties: { bits: { type: "integer", minimum: 512, maximum: 16384 } },
      },
    },
    async handler(
      request: FastifyRequest<{ Params: { bits: string } }>,
      reply: FastifyReply,
    ) {
      if (!gpuEnabled()) return fail(reply, 503, { error: "GPU features disabled" });
      const bits = Number.parseInt(request.params.bits, 10);
      if (!Number.isInteger(bits) || bits < 512 || bits > 16384) {
        return fail(reply, 400, { error: "bits must be an integer between 512 and 16384" });
      }
      const { code, payload: result } = await runBridge("quantum-estimate", { bits }, 15_000);
      if (code !== 0 || result.error) {
        return fail(reply, 502, { error: "quantum_estimation_failed" });
      }
      return result;
    },
  });

  server.post("/v1/gpu/rl/plan", {
    schema: {
      tags: ["gpu"],
      summary: "RL-based migration plan (proxied to planner microservice; not GPU-gated)",
      body: RLPlanSchema,
    },
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
    async handler(request: FastifyRequest<{ Body: { cbom: Record<string, unknown> } }>, reply: FastifyReply) {
      try {
        const resp = await fetch(`${PLANNER_URL}/rl/plan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request.body.cbom),
          signal: AbortSignal.timeout(30_000),
        });
        if (!resp.ok) throw new Error(`planner returned ${resp.status}`);
        return (await resp.json()) as Record<string, unknown>;
      } catch (err) {
        request.log.error(err);
        return fail(reply, 503, { error: "rl_planner_unavailable" });
      }
    },
  });
}

interface SideChannelBody {
  simulated?: boolean;
  leakage_prob?: number;
  implementation_cmd?: string[];
  n_traces?: number;
}
