# syntax=docker/dockerfile:1.7
#
# Minimal Next.js health placeholder (decision F-9). No authentication UI, no business UI,
# no client-side data fetching. Base image pinned by minor version; digest pinning is F-5
# and is NOT done yet.

# Node 20 reached end of life in April 2026; 22 is the active LTS line.
ARG NODE_IMAGE=node:22-alpine

# ---------------------------------------------------------------- deps
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.12.0 --activate
COPY package.json pnpm-lock.yaml ./
# --frozen-lockfile fails the build if the lockfile and manifest disagree.
RUN pnpm install --frozen-lockfile

# ---------------------------------------------------------------- build
FROM ${NODE_IMAGE} AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.12.0 --activate
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN pnpm build

# ---------------------------------------------------------------- runtime
FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# The node image already provides an unprivileged `node` user (uid 1000).
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public

# The tmpfs mount point exists in the image rather than being created by the runtime, for the
# same reason as the backend's: a destination Docker has to create is a write to the container
# layer, which `read_only: true` forbids (T-5.1). Nothing has been observed writing here — every
# page is force-dynamic and every fetch no-store — but Next's file cache lives at this path and
# the case actions call revalidatePath, so it is mounted rather than gambled on.
RUN mkdir -p /app/.next/cache && chown node:node /app/.next/cache

USER node
EXPOSE 3000
CMD ["node", "server.js"]
