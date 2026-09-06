/** @type {import('next').NextConfig} */
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig = {
  // Linting is a separate, stricter step (`pnpm lint`) with its own flat config, and it
  // runs in CI before the build. Repeating a weaker version of it here would only hide
  // which one failed.
  eslint: { ignoreDuringBuilds: true },
  // Required by frontend/Dockerfile, which copies .next/standalone into the runtime image.
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
