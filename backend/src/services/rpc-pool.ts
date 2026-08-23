import {
  createPublicClient,
  createWalletClient,
  http,
  type Account,
  type Address,
  type HttpTransport,
  type PublicClient,
  type WalletClient,
} from "viem";
import type { Chain } from "viem";
import { CHAIN } from "../config.js";

const COOLDOWN_MS = 60_000;

function loadRpcUrls(): string[] {
  const pooled = process.env.QTRUST_RPC_URLS ?? "";
  const urls: string[] = [];
  for (const url of pooled.split(",").map((s) => s.trim()).filter(Boolean)) {
    if (!urls.includes(url)) urls.push(url);
  }
  const fallback = process.env.QTRUST_BASE_SEPOLIA_RPC || "http://127.0.0.1:8545";
  if (!urls.includes(fallback)) urls.push(fallback);
  return urls;
}

const endpoints = loadRpcUrls().map((url) => ({ url, downUntil: 0 }));

let cursor = 0;

const publicClients = new Map<string, PooledPublicClient>();
const walletClients = new Map<string, PooledWalletClient>();

function publicClientFor(url: string): PooledPublicClient {
  let client = publicClients.get(url);
  if (!client) {
    client = createPublicClient({
      chain: CHAIN,
      transport: http(url, { timeout: 30_000 }),
    });
    publicClients.set(url, client);
  }
  return client as PooledPublicClient;
}

function walletClientFor(account: Account | Address, url: string): PooledWalletClient {
  const address = typeof account === "string" ? account : account.address;
  const key = `${address.toLowerCase()}|${url}`;
  let client = walletClients.get(key);
  if (!client) {
    client = createWalletClient({
      account: typeof account === "string" ? (account as Address) : account,
      chain: CHAIN,
      transport: http(url),
    });
    walletClients.set(key, client);
  }
  return client as PooledWalletClient;
}

function isTransportFailure(err: unknown): boolean {
  const name = (err as { name?: string } | null)?.name;
  return (
    name === "TransportError" ||
    name === "HttpRequestError" ||
    name === "HTTPError" ||
    name === "TimeoutError" ||
    name === "WebSocketRequestError"
  );
}

async function withFailover<T>(run: (url: string) => Promise<T>): Promise<T> {
  let lastError: unknown;
  const total = endpoints.length;
  for (let offset = 0; offset < total; offset++) {
    const index = (cursor + offset) % total;
    const endpoint = endpoints[index];
    if (endpoint.downUntil > Date.now()) continue;
    try {
      const result = await run(endpoint.url);
      endpoint.downUntil = 0;
      cursor = index;
      return result;
    } catch (err) {
      if (!isTransportFailure(err)) throw err;
      lastError = err;
      endpoint.downUntil = Date.now() + COOLDOWN_MS;
    }
  }
  throw lastError ?? new Error(`No RPC endpoints available (${endpoints.map((e) => e.url).join(", ")})`);
}

function pooledClient<C extends object>(clientForUrl: (url: string) => C): C {
  return new Proxy({} as C, {
    get(_target, prop: string | symbol) {
      const current = clientForUrl(endpoints[cursor % endpoints.length].url);
      const value = Reflect.get(current as object, prop, current) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      return (...args: unknown[]) =>
        withFailover(async (url: string) => {
          const client = clientForUrl(url);
          const fn = Reflect.get(client as object, prop, client) as (
            ...fnArgs: unknown[]
          ) => unknown;
          return fn(...args);
        });
    },
    has(_target, prop: string | symbol) {
      return prop in (clientForUrl(endpoints[cursor % endpoints.length].url) as object);
    },
  }) as C;
}

export type PooledPublicClient = PublicClient<HttpTransport, Chain>;
export type PooledWalletClient = WalletClient<HttpTransport, Chain, Account>;

export function getPublicClient(): PooledPublicClient {
  return pooledClient(publicClientFor);
}

export function getWalletClient(account: Account): PooledWalletClient {
  return pooledClient((url) => walletClientFor(account, url));
}
