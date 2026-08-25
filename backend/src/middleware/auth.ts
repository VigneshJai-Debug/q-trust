import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { createHash, timingSafeEqual } from 'node:crypto';

const PRIVATE_IP_PATTERNS = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^::1$/,
  /^0:0:0:0:0:0:0:1$/,
];

const SHELL_META_CHARS = /[;|&$`\\n]/;

function isPrivateOrBlockedHost(host: string): boolean {
  const lower = host.toLowerCase();
  if (lower === 'localhost') return true;
  if (lower === '0.0.0.0') return true;
  return PRIVATE_IP_PATTERNS.some((pattern) => pattern.test(lower));
}

/** Length-independent comparison that never short-circuits on content. */
function safeEquals(a: string, b: string): boolean {
  const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest();
  return timingSafeEqual(sha(a), sha(b)) && a === b;
}

/**
 * API-key gate usable both as a route `preHandler` and as an instance hook.
 * Halting is signaled by returning the (already-sent) reply.
 *
 * Policy: fail-closed whenever QTRUST_API_KEYS is configured OR the process
 * runs in production; pure-local dev with no key management stays open so the
 * scanner/GPU demo flows work out of the box (mirrors server.ts semantics).
 */
export async function requireApiKey(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<unknown> {
  const configuredKeys = process.env.QTRUST_API_KEYS;
  const isProduction = process.env.NODE_ENV === 'production';
  if (!configuredKeys) {
    if (!isProduction) {
      // Pure-local dev with no key management configured: keep endpoints open,
      // mirroring server.ts API_KEY_REQUIRED semantics.
      return undefined;
    }
    return reply.code(500).send({ error: 'Server misconfigured: no API keys set' });
  }

  const validKeys = configuredKeys
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean);

  const providedKey = request.headers['x-api-key'];
  if (
    typeof providedKey !== 'string' ||
    !validKeys.some((k) => safeEquals(k, providedKey))
  ) {
    return reply.code(401).send({ error: 'Invalid or missing API key' });
  }
  return undefined;
}

export function validateTarget(
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
): void {
  const body = request.body as Record<string, unknown> | undefined;
  if (!body || typeof body !== 'object') {
    reply.code(400).send({ error: 'Request body is required' });
    return;
  }

  const target = body.target ?? body.directory;
  if (target === undefined) {
    reply
      .code(400)
      .send({ error: 'Missing required field: target or directory' });
    return;
  }

  if (typeof target !== 'string') {
    reply.code(400).send({ error: 'Target must be a string' });
    return;
  }

  if (target.length === 0) {
    reply.code(400).send({ error: 'Target cannot be empty' });
    return;
  }

  if (target.length > 2048) {
    reply
      .code(400)
      .send({ error: 'Target exceeds maximum length of 2048 characters' });
    return;
  }

  if (SHELL_META_CHARS.test(target)) {
    reply
      .code(400)
      .send({ error: 'Target contains invalid characters' });
    return;
  }

  try {
    const parsed = new URL(target);
    if (isPrivateOrBlockedHost(parsed.hostname)) {
      reply
        .code(400)
        .send({ error: 'Target resolves to a private or blocked address' });
      return;
    }
  } catch {
    const hostname = target.split(':')[0].split('/')[0];
    if (isPrivateOrBlockedHost(hostname)) {
      reply
        .code(400)
        .send({ error: 'Target resolves to a private or blocked address' });
      return;
    }
  }
}

export function requestLogger(
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
): void {
  const start = Date.now();
  const { method, url } = request;
  const ip =
    request.headers['x-forwarded-for'] ||
    request.headers['x-real-ip'] ||
    request.socket.remoteAddress ||
    'unknown';
  const userAgent = request.headers['user-agent'] || 'unknown';

  reply.raw.on('finish', () => {
    const duration = Date.now() - start;
    const log = {
      method,
      url,
      ip: Array.isArray(ip) ? ip[0] : ip,
      userAgent,
      statusCode: reply.statusCode,
      duration,
    };
    request.log.info(log, 'request completed');
  });
}

export function securityHeaders(
  this: FastifyInstance,
  _request: FastifyRequest,
  reply: FastifyReply,
): void {
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('X-XSS-Protection', '1; mode=block');
  reply.header(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains',
  );
  reply.header('Content-Security-Policy', "default-src 'self'");
  reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
}

export function gracefulShutdown(
  server: FastifyInstance,
  signal: string,
): void {
  const handler = async () => {
    server.log.info({ signal }, 'Received signal, shutting down gracefully');
    try {
      await server.close();
      server.log.info('Server closed successfully');
      process.exit(0);
    } catch (err) {
      server.log.error(err, 'Error during shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', handler);
  process.on('SIGINT', handler);
}
