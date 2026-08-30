# AegisNet web

Next.js placeholder for the `web` container. It serves one page and one health route
(`GET /api/health` → `{"status":"ok"}`) so the Compose topology can be built and
health-checked end to end. There is no authentication UI, no business UI and no
client-side data fetching (decision F-9). The analyst dashboard is Milestone 4.

```bash
corepack enable          # provides the pnpm version pinned in package.json
pnpm install --frozen-lockfile
pnpm typecheck
pnpm build
```
