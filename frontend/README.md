# AegisNet — analyst dashboard

Next.js App Router, React 19, TypeScript. Milestone 4; the decisions behind it are
[ADR-026](../docs/adr/ADR-026-the-dashboard-holds-the-session-and-the-browser-holds-nothing.md).

## What is here today (Chunk 18)

- **Sign in and sign out.** The API's access token and refresh cookie are kept in this app's own
  `HttpOnly` cookies. The browser never holds a credential and never learns the API's address.
- **The incident queue**: every case correlation opened, newest first, filtered by status,
  minimum severity and open-only, paginated by the API's keyset cursor.
- **The boundary**: `src/lib/api/schemas.ts` restates the API's DTOs as zod schemas and every
  response is parsed before a component sees it.

Incident detail, the timeline, status transitions and notes arrive in Chunk 19; asset screens,
the audit viewer, Playwright and the committed screenshots in Chunk 20.

## Layout

| Path | What it is |
|---|---|
| `src/app/login/` | The form, its server actions, and the only client component here |
| `src/app/incidents/` | The queue and its filters, server-rendered |
| `src/components/` | Badges and timestamps — display only, no data access |
| `src/lib/api/` | The one module that talks to the API, and the schemas it parses with |
| `src/lib/session.ts` | Cookie names, lifetimes and the role check the UI draws controls from |
| `src/middleware.ts` | Rotates an expired session before the render; sends the rest to `/login` |

## Commands

```bash
pnpm install          # the locked set
pnpm dev              # http://localhost:3000, expects the API at AEGISNET_API_URL
pnpm typecheck        # tsc --noEmit
pnpm lint             # eslint, including the dangerouslySetInnerHTML ban (T-1.3)
pnpm test             # vitest
pnpm build            # next build (standalone, for the container)
```

`AEGISNET_API_URL` defaults to `http://localhost:8000`; Compose sets it to `http://api:8000`.
It is a **server** variable on purpose — see ADR-026.

## Rules this app is held to

- `dangerouslySetInnerHTML`, `innerHTML` and `outerHTML` are banned by the linter (T-1.3).
  Every string rendered here came from a packet somebody else sent.
- No token, and no API address, may reach the browser (T-2.4).
- Severity and status are shown as words as well as colour; contrast meets WCAG AA.
- The API decides what a role may do. This app only decides which controls to draw.
