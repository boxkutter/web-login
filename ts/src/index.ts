/** Shared by the screens and by an app's own pages: what the server says and the small decisions made from it. */

export type SignInNext = "done" | "mfa" | "enrol" | "verify";

/** The sign-in options the server publishes (`GET /v1/auth/options`). */
export interface Options {
  local_login: boolean;
  registration_open: boolean;
  providers: { key: string; name: string }[];
}

export const DEFAULT_OPTIONS: Options = { local_login: true, registration_open: false, providers: [] };

export interface Result<T> {
  ok: boolean;
  status: number;
  data: T;
  error: string;
}

/** Only same-site paths are honoured after sign-in, so a crafted link cannot send a person elsewhere. */
export function safeNext(next: string | undefined | null, fallback = "/"): string {
  return next && /^\/(?!\/)[A-Za-z0-9/_\-?=&%.]*$/.test(next) ? next : fallback;
}

/** The answer of a sign-in route for a session state the server reports. */
export function nextForState(state: string): SignInNext {
  return state === "mfa_pending" ? "mfa" : state === "mfa_enrol" ? "enrol" : state === "verify_email" ? "verify" : "done";
}

/** Where the browser goes once a step is finished. */
export interface Routes {
  home: string;
  login: string;
  register: string;
  forgot: string;
  enrol: string;
  verify: string;
  /** The address that starts a single sign-on login for a provider key. */
  oidcStart: (key: string) => string;
}

export const DEFAULT_ROUTES: Routes = {
  home: "/",
  login: "/login",
  register: "/register",
  forgot: "/forgot-password",
  enrol: "/account/security",
  verify: "/account/verify",
  oidcStart: (key) => `/api/session/oidc/${encodeURIComponent(key)}/start`,
};

export function destination(next: SignInNext | string, routes: Routes, done: string): string {
  return next === "enrol" ? routes.enrol : next === "verify" ? routes.verify : done;
}

/** Where the browser talks to the app's own server (route handlers that hold the cookie). */
export interface ClientPaths {
  /** Sign-in routes that set the cookie: `${session}/login`, `/mfa`, `/register`, `/oidc/<key>`. */
  session: string;
  /** The proxy that forwards a signed-in call to the API. */
  api: string;
  /** Routes for calls made before sign-in: `${pub}/forgot`, `/reset`, `/verify`. */
  pub: string;
}

export const DEFAULT_PATHS: ClientPaths = { session: "/api/session", api: "/api/bff", pub: "/api/public" };

export interface Client {
  session<T = { next: SignInNext }>(path: string, body: unknown): Promise<Result<T>>;
  call<T = unknown>(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<Result<T>>;
  publicCall<T = { ok: boolean; detail: string }>(name: string, body: unknown): Promise<Result<T>>;
}

function problem(data: unknown): string {
  const d = data as { detail?: string; errors?: { msg: string }[] } | null;
  return d?.errors?.[0]?.msg ?? d?.detail ?? "That did not work.";
}

const OFFLINE = "The service is not reachable. Try again shortly.";

/** A small fetch client for the three kinds of call. Pass a different `fetchImpl` in tests. */
export function createClient(paths: Partial<ClientPaths> = {}, fetchImpl: typeof fetch = (...a) => fetch(...a)): Client {
  const p = { ...DEFAULT_PATHS, ...paths };
  async function send<T>(url: string, method: string, body: unknown, headers: Record<string, string> = {}, onUnauthorised?: () => void): Promise<Result<T>> {
    const h = { ...headers };
    if (body !== undefined) h["content-type"] = "application/json";
    try {
      const r = await fetchImpl(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
      const data = r.status === 204 ? null : await r.json().catch(() => null);
      if (r.status === 401 && onUnauthorised) onUnauthorised();
      return { ok: r.ok, status: r.status, data: data as T, error: r.ok ? "" : problem(data) };
    } catch {
      return { ok: false, status: 0, data: null as T, error: OFFLINE };
    }
  }
  return {
    session: (path, body) => send(`${p.session}/${path}`, "POST", body),
    call: (method, path, body, headers) => send(`${p.api}/${path}`, method, body, headers),
    publicCall: (name, body) => send(`${p.pub}/${name}`, "POST", body),
  };
}
