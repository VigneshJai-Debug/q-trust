/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Allow the API to live on a different origin in development.
  experimental: {
    // React 19 / Next 16 may flag missing server actions config — opt in here.
    serverActions: {
      allowedOrigins: ["localhost:3000", "localhost:3001"],
    },
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
