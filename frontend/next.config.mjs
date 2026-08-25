/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Allow the API to live on a different origin in development.
  experimental: {
    // React 19 / Next 16 may flag missing server actions config — opt in here.
    serverActions: {
      allowedOrigins: ["localhost:3000", "localhost:3001"],
    },
  },
  // Security headers
  async headers() {
    // Next.js dev server needs 'unsafe-eval' for its HMR runtime; production
    // builds do not. connect-src follows the configured API origin instead of
    // a hardcoded localhost (audit FE-1 / FE-2).
    const isDev = process.env.NODE_ENV !== "production";
    const apiBase = process.env.NEXT_PUBLIC_QTRUST_API_URL ?? "http://localhost:3001";
    const scriptSrc = isDev ? "'self' 'unsafe-eval'" : "'self'";
    const csp = [
      "default-src 'self'",
      `script-src ${scriptSrc}`,
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' data: https://fonts.gstatic.com",
      "img-src 'self' data: https://ipfs.io https://explorer.walletconnect.com",
      `connect-src 'self' ${apiBase} ${apiBase.replace(/^http/, "ws")} https://sepolia.base.org https://mainnet.base.org wss://relay.walletconnect.com https://relay.walletconnect.com https://explorer.walletconnect.com`,
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
    ].join("; ");
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "X-XSS-Protection", value: "1; mode=block" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Content-Security-Policy", value: csp },
        ],
      },
    ];
  },
  // Rewrite /api/* to the Fastify backend (avoids CORS in dev).
  async rewrites() {
    const apiBase = process.env.NEXT_PUBLIC_QTRUST_API_URL ?? "http://localhost:3001";
    return [
      {
        source: "/api/:path*",
        destination: `${apiBase}/:path*`,
      },
    ];
  },
};

export default nextConfig;
