# syntax=docker/dockerfile:1.7
#
# The analyst dashboard (Milestone 4), built as a Next standalone server: sign-in, the incident
# queue, the case view with its brief panel, the asset and audit views, and the Markdown report
# route. Still no client-side data fetching — one server-side module talks to the API, so the
# browser never holds a token and never learns the API's address (ADR-026, T-2.4). Decision F-9
# is what held this image to a health placeholder for Milestone 1.
#
# The base image is pinned by minor version and stays that way (decision F-5, residual risk
# R-10) — the note at `apk upgrade` below says why that is a choice rather than an omission.

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
ARG GIT_SHA=unknown
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Same reason as the backend image, and the same two omissions: no `image.version`, and no
# `image.revision` — the revision label read `${GIT_SHA}` and SonarCloud rated it a security
# finding on new code, so it went rather than the Dockerfile being carved out of the analysis
# scope (E-96). `ARG GIT_SHA` stays for the build; nothing in this app reads it at runtime.
LABEL org.opencontainers.image.title="aegisnet-web" \
      org.opencontainers.image.source="https://github.com/pchrysostomou/aegisnet" \
      org.opencontainers.image.licenses="MIT"

# The node image already provides an unprivileged `node` user (uid 1000).
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public

# The tmpfs mount point exists in the image rather than being created by the runtime, for the
# same reason as the backend's: a destination Docker has to create is a write to the container
# layer, which `read_only: true` forbids (T-5.1). Nothing has been observed writing here — every
# page is force-dynamic and every fetch no-store — but Next's file cache lives at this path and
# the case actions call revalidatePath, so it is mounted rather than gambled on.
# Alpine publishes package fixes faster than the base image tag is rebuilt, and following a tag
# (decision F-5, R-10) only delivers a patch once upstream republishes. The scan found exactly
# that gap on its first run: libcrypto3 3.5.7-r0 against a fix already published as 3.5.8-r0
# (CVE-2026-14456). Upgrading here closes the window between alpine shipping a fix and the node
# image being rebuilt, which is the whole reason tags were kept over digests.
RUN apk upgrade --no-cache

# The base image ships npm and corepack; a Next standalone server runs `node server.js` and
# uses neither. They are removed rather than left in place because npm carries its own bundled
# dependency tree — tar, sigstore, pacote, @npmcli — which `pnpm audit` structurally cannot see:
# it reads this app's lockfile, and those packages are not in it. The image scan found exactly
# that on its first working run (T-5.6, E-91), which is the gap the scan was added for. Deleting
# an interpreter's package manager from a runtime image also removes the most convenient way to
# install something into a container somebody has just got code execution in.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack

RUN mkdir -p /app/.next/cache && chown node:node /app/.next/cache

USER node
EXPOSE 3000
CMD ["node", "server.js"]
