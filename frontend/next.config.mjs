/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredBy: false,
  // Allow the API to live on a different origin in development.
  experimental: {
    // React 19 / Next 16 may flag missing server actions config — opt in here.
    serverActions: {
      allowedOrigins: ["localhost:3000", "localhost:3001"],
    },
  },
  // Security headers
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "X-XSS-Protection", value: "1; mode=block" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          {
            key: "Content-Security-Policy",
            value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://ipfs.io; connect-src 'self' https://sepolia.base.org https://mainnet.base.org http://localhost:3001",
          },
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
