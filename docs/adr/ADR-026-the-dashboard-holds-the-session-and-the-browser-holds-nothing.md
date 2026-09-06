# ADR-026 — The dashboard holds the session, and the browser holds nothing

- Status: accepted
- Date: 2026-09-06
- Milestone: 4 (Chunk 18); the first of the analyst dashboard

## Context

Milestone 4 puts a UI in front of the API built in Milestones 1 to 3. That means answering a
question the backend has so far been able to avoid: where does an analyst's session live.

The API issues a short-lived HS256 access token and a rotating refresh cookie with reuse
detection (ADR-016). Those are good primitives, and the obvious thing to do — hand them to the
browser and let a React app call the API directly — would waste them. An access token in
`localStorage` is readable by any script that runs on the page, and this is a dashboard whose
entire job is rendering strings that arrived in packets somebody else sent: DNS query names,
HTTP hosts, Suricata signatures, and from Chunk 19, analyst notes. T-1.3 is the threat this
milestone is most exposed to, and the blast radius of an XSS bug is decided here, before any
of that content is rendered.

## Decision

### The browser never holds a credential

The browser talks to Next; Next talks to the API. `src/lib/api/client.ts` is the only module
that calls the API, it runs on the server, and the API's address arrives in `AEGISNET_API_URL`
— a server variable, never a `NEXT_PUBLIC_` one, because a public variable is baked into the
bundle at build time and read by anyone with the page.

The session is two `HttpOnly`, `SameSite=Lax` cookies that Next issues and only Next reads: the
API's access token, and the API's refresh cookie carried across as an opaque value. Script on
the page cannot read either. An XSS bug in this dashboard is still serious — it can act as the
analyst while the page is open — but it cannot walk away with a credential that keeps working
afterwards, and that is the difference this decision buys.

The access cookie's lifetime is the token's own `expires_in`, less a second. "No access
cookie" and "the token has expired" are therefore the same condition, and there is no second
copy of the expiry to keep in step with the first.

### Refreshing happens in middleware, because a render cannot write a cookie

Next server components can read cookies and not write them, so a token that expires during a
render has nowhere to put its replacement. Middleware runs before the render and can do both:
when the access cookie has gone and the session cookie has not, it rotates the pair, puts the
new values on the onward request so this render sees them, and on the response so the browser
keeps them. When the API refuses — including the case where a replayed refresh token made it
revoke the whole chain on purpose — both cookies are cleared and the analyst lands on the login
form with `expired=1`.

The alternative was to bounce an analyst to the login form every fifteen minutes. That teaches
people to keep a password manager open on the incident queue, which is a worse security outcome
than the one it was protecting.

Middleware is a convenience, not the boundary. The API enforces its own permissions on every
request; a forged or hand-edited cookie buys nothing, and no page trusts what middleware says.

### The API's answers are parsed, not assumed

`src/lib/api/schemas.ts` restates the DTOs as zod schemas, and every response is parsed before
a component sees it. A renamed or dropped field fails in one place, loudly, rather than as an
`undefined` halfway down a tree. The schemas are deliberately strict and deliberately partial:
a field this dashboard does not render is a field it does not validate, but a field it does
render must be exactly what the contract says.

Errors arrive in the documented envelope and become an `ApiError` carrying status, code and
correlation id, so callers branch on facts. A refused workflow transition is a `409` and a
normal answer, not a fault (ADR-024).

### `dangerouslySetInnerHTML` is banned by the linter

Not discouraged — banned, with `innerHTML` and `outerHTML` assignment alongside it, by a
`no-restricted-syntax` rule that names T-1.3 in its message. React escapes text nodes; that
attribute is the one escape hatch that would undo it, and there is no legitimate use for it
here. The `SafeMarkdown` renderer that Chunk 19 needs for note bodies will build elements
rather than HTML, so it does not need one either.

The rule is proven rather than assumed: adding a component that uses the attribute fails
`pnpm lint`, which is how it was checked before being relied on.

### Server components, one stylesheet, no framework

Lists and detail pages are server components: the data never reaches the browser as JSON it
would then have to re-render, and there is no client-side store to drift from the API. The
only client component in this chunk is the login form, which needs `useActionState` to show a
pending state.

Styling is one hand-written stylesheet. A utility framework would add a build step and a
supply-chain surface to solve a problem an app made of tables and text does not have. Colours
are checked for WCAG AA contrast, and severity is shown as a number *and* a word, because
colour alone is not information every reader can see.

Filters are a plain `GET` form, so the queue's state lives in the URL: a filtered view can be
sent to a colleague by copying the address bar, and the back button does what it says.

## Consequences

- Positive: an XSS bug cannot exfiltrate a credential. The session outlives the page only in
  cookies the page cannot read.
- Positive: the API's address and every token stay inside the server process. The browser's
  view of AegisNet is one origin with no secrets in it.
- Positive: a contract drift between backend and frontend fails at the boundary with a message
  naming the field, rather than rendering `undefined` into a case an analyst is reading.
- Negative: every page is server-rendered on demand, so each navigation is a round trip through
  Next to the API. For a dashboard with tens of cases this is the right trade; for a view that
  needs sub-second interaction it would not be, and that view would need a different answer.
- Negative: middleware calls the API on the first request after an access cookie expires, which
  puts a network hop in front of that render. The alternative put a login form there.
- Neutral: `eslint-config-next` is not used. It pins ESLint to a 9.x release that is already
  deprecated; the flat config here uses ESLint 10 with `typescript-eslint` and the React hooks
  plugin, and Next's own build-time lint is turned off so there is one linter with one config.
