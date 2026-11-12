/**
 * Next.js server helpers: the browser never holds the session token. It lives in an HttpOnly cookie that only these routes
 * set, and the screens learn only where to go next. Import from "@boxkutter/web-login/server" in route handlers and server
 * components.
 */
import { cookies } from "next/headers";
import { NextResponse, type NextRequest } from "next/server";
import { nextForState } from "../index";

export interface ServerConfig {
  /** The sign-in API's internal address (never exposed to the browser). */
  apiUrl: string;
  sessionCookie: string;
  /** Holds the half-finished sign-in between the password and the second factor. */
  mfaCookie: string;
  sessionMaxAge?: number;
  mfaMaxAge?: number;
  /** Cookies are marked Secure when this returns true (default: in production). */
  secureCookies?: () => boolean;
}

export interface SignInRouteOptions {
  /** The half-finished sign-in's token, for the second step. */
  bearer?: string;
  /** Only these fields of the browser's JSON are forwarded. */
  pick?: string[];
}

export function sameOrigin(req: NextRequest): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return false;
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

export const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function createLoginServer(config: ServerConfig) {
  const apiUrl = config.apiUrl.replace(/\/$/, "");
  const sessionMaxAge = config.sessionMaxAge ?? 12 * 60 * 60;
  const mfaMaxAge = config.mfaMaxAge ?? 5 * 60;
  const secure = config.secureCookies ?? (() => process.env.NODE_ENV === "production");
  const base = () => ({ httpOnly: true, sameSite: "lax" as const, secure: secure(), path: "/" });

  const setSession = (res: NextResponse, token: string) => {
    res.cookies.set(config.sessionCookie, token, { ...base(), maxAge: sessionMaxAge });
    res.cookies.delete(config.mfaCookie);
  };
  const setPendingMfa = (res: NextResponse, token: string) => res.cookies.set(config.mfaCookie, token, { ...base(), maxAge: mfaMaxAge });
  const clearSession = (res: NextResponse) => {
    res.cookies.delete(config.sessionCookie);
    res.cookies.delete(config.mfaCookie);
  };

  async function readBody(req: NextRequest): Promise<Record<string, unknown> | null> {
    try {
      const body = await req.json();
      return body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  }

  const pickFields = (body: Record<string, unknown>, pick?: string[]) => (pick ? Object.fromEntries(Object.entries(body).filter(([k]) => pick.includes(k))) : body);

  /** Forward a JSON body to the API and turn the token in the answer into an HttpOnly cookie. */
  async function signInRoute(req: NextRequest, apiPath: string, opts: SignInRouteOptions = {}): Promise<NextResponse> {
    if (!sameOrigin(req)) return NextResponse.json({ detail: "Cross-site request refused." }, { status: 403 });
    const body = await readBody(req);
    if (!body) return NextResponse.json({ detail: "Bad request." }, { status: 400 });
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (opts.bearer) headers.Authorization = `Bearer ${opts.bearer}`;
    const ua = req.headers.get("user-agent");
    if (ua) headers["user-agent"] = ua;
    const fwd = req.headers.get("x-forwarded-for");
    if (fwd) headers["x-forwarded-for"] = fwd;
    let r: Response;
    try {
      r = await fetch(`${apiUrl}${apiPath}`, { method: "POST", headers, body: JSON.stringify(pickFields(body, opts.pick)), cache: "no-store" });
    } catch {
      return NextResponse.json({ detail: "The service is not reachable. Try again shortly." }, { status: 503 });
    }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) return NextResponse.json({ detail: data.detail ?? "That did not work." }, { status: r.status });
    const res = NextResponse.json({ next: nextForState(data.state) });
    if (data.state === "mfa_pending") setPendingMfa(res, data.token);
    else setSession(res, data.token);
    return res;
  }

  /** The second step: the pending token comes from its own cookie, never from the browser's body. */
  async function mfaRoute(req: NextRequest): Promise<NextResponse> {
    const pending = req.cookies.get(config.mfaCookie)?.value;
    if (!pending) return NextResponse.json({ detail: "Sign in again." }, { status: 401 });
    return signInRoute(req, "/v1/auth/mfa", { bearer: pending, pick: ["code", "recovery_code"] });
  }

  /** A call made before sign-in (reset links, email confirmation): origin-checked, JSON in, a plain answer out. */
  async function publicPost(req: NextRequest, apiPath: string, pick: string[]): Promise<NextResponse> {
    if (!sameOrigin(req)) return NextResponse.json({ detail: "Cross-site request refused." }, { status: 403 });
    const body = await readBody(req);
    if (!body) return NextResponse.json({ detail: "Bad request." }, { status: 400 });
    const headers: Record<string, string> = { "content-type": "application/json" };
    const fwd = req.headers.get("x-forwarded-for");
    if (fwd) headers["x-forwarded-for"] = fwd;
    let r: Response;
    try {
      r = await fetch(`${apiUrl}${apiPath}`, { method: "POST", headers, body: JSON.stringify(pickFields(body, pick)), cache: "no-store" });
    } catch {
      return NextResponse.json({ detail: "The service is not reachable. Try again shortly." }, { status: 503 });
    }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) return NextResponse.json({ detail: data?.errors?.[0]?.msg ?? data?.detail ?? "That did not work." }, { status: r.status });
    return NextResponse.json({ ok: true, detail: data?.detail ?? "" });
  }

  async function sessionToken(): Promise<string | null> {
    return (await cookies()).get(config.sessionCookie)?.value ?? null;
  }

  /** Call the API as the signed-in person (server components and route handlers only). */
  async function apiGet<T>(path: string, extraHeaders: Record<string, string> = {}): Promise<{ status: number; data: T | null }> {
    const token = await sessionToken();
    const headers: Record<string, string> = { ...extraHeaders };
    if (token) headers.Authorization = `Bearer ${token}`;
    try {
      const r = await fetch(`${apiUrl}${path}`, { headers, cache: "no-store" });
      const data = r.headers.get("content-type")?.includes("json") ? ((await r.json()) as T) : null;
      return { status: r.status, data: r.ok ? data : null };
    } catch {
      return { status: 503, data: null };
    }
  }

  return { config: { ...config, apiUrl }, sameOrigin, setSession, setPendingMfa, clearSession, signInRoute, mfaRoute, publicPost, sessionToken, apiGet };
}

export type LoginServer = ReturnType<typeof createLoginServer>;
