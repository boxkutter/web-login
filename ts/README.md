# @boxkutter/web-login

Sign-in screens for React and Next.js apps that use the web-login server, plus Next.js route helpers that keep the session token in an HttpOnly cookie. See the repository README.

Entry points: `@boxkutter/web-login` (types, `safeNext`, fetch client), `/react` (the screens), `/server` (Next.js route helpers, including `oidcStartRoute` and `proxyRoute`) and `/styles.css`. React and Next.js are optional peer dependencies. Checks: `npm run typecheck && npm test && npm run build`.
