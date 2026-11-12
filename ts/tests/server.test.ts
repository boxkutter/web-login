import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createLoginServer, sameOrigin } from "../src/server";

const login = createLoginServer({ apiUrl: "http://api.test/", sessionCookie: "app_session", mfaCookie: "app_mfa", secureCookies: () => true });

function req(body: unknown, headers: Record<string, string> = {}, cookies = "") {
  return new NextRequest("http://app.test/api/session/login", {
    method: "POST",
    headers: { host: "app.test", origin: "http://app.test", "content-type": "application/json", ...(cookies ? { cookie: cookies } : {}), ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const upstream = (status: number, body: unknown) => vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(body), { status }));

afterEach(() => vi.restoreAllMocks());

describe("sameOrigin", () => {
  it("accepts this site and refuses a missing, foreign or malformed origin", () => {
    expect(sameOrigin(req({}))).toBe(true);
    expect(sameOrigin(req({}, { origin: "http://evil.test" }))).toBe(false);
    expect(sameOrigin(req({}, { origin: "not a url" }))).toBe(false);
    const noOrigin = new NextRequest("http://app.test/x", { method: "POST", headers: { host: "app.test" } });
    expect(sameOrigin(noOrigin)).toBe(false);
    expect(sameOrigin(req({}, { "x-forwarded-host": "app.test", host: "internal:3000" }))).toBe(true);
  });
});

describe("signInRoute", () => {
  it("turns the token into an HttpOnly cookie and tells the browser only where to go", async () => {
    const f = upstream(200, { token: "SECRET-TOKEN", state: "full" });
    const res = await login.signInRoute(req({ email: "a@b.test", password: "pw", admin: true }), "/v1/auth/login", { pick: ["email", "password"] });
    expect(await res.json()).toEqual({ next: "done" });
    const cookie = res.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(/app_session=SECRET-TOKEN/);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/Secure/i);
    expect(cookie).toMatch(/SameSite=lax/i);
    const [url, init] = f.mock.calls[0]!;
    expect(url).toBe("http://api.test/v1/auth/login");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ email: "a@b.test", password: "pw" }); // only the picked fields
  });

  it("keeps a half-finished sign-in in its own cookie", async () => {
    upstream(200, { token: "PENDING", state: "mfa_pending" });
    const res = await login.signInRoute(req({ email: "a", password: "b" }), "/v1/auth/login");
    expect(await res.json()).toEqual({ next: "mfa" });
    const cookie = res.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(/app_mfa=PENDING/);
    expect(cookie).not.toMatch(/app_session=PENDING/);
  });

  it("passes on the server's refusal without the token, and survives a bad body, a foreign origin and an outage", async () => {
    upstream(401, { detail: "Email or password is not right.", extra: "ignored" });
    const bad = await login.signInRoute(req({ email: "a", password: "b" }), "/v1/auth/login");
    expect(bad.status).toBe(401);
    expect(await bad.json()).toEqual({ detail: "Email or password is not right." });
    expect(bad.headers.get("set-cookie")).toBeNull();
    expect((await login.signInRoute(req("not json"), "/x")).status).toBe(400);
    expect((await login.signInRoute(req([1, 2]), "/x")).status).toBe(400);
    expect((await login.signInRoute(req({}, { origin: "http://evil.test" }), "/x")).status).toBe(403);
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("down"));
    expect((await login.signInRoute(req({}), "/x")).status).toBe(503);
  });
});

describe("mfaRoute", () => {
  it("takes the pending token from its cookie, never from the body", async () => {
    expect((await login.mfaRoute(req({ code: "123456" }))).status).toBe(401);
    const f = upstream(200, { token: "FULL", state: "full" });
    const res = await login.mfaRoute(req({ code: "123456", token: "attacker" }, {}, "app_mfa=PENDING-COOKIE"));
    const init = f.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer PENDING-COOKIE");
    expect(JSON.parse(init.body as string)).toEqual({ code: "123456" });
    expect(res.headers.get("set-cookie")).toMatch(/app_session=FULL/);
  });
});

describe("publicPost", () => {
  it("forwards only the listed fields and reports the first field error", async () => {
    const f = upstream(422, { errors: [{ msg: "Use at least 12 characters." }], detail: "x" });
    const res = await login.publicPost(req({ token: "t", new_password: "short", is_admin: true }), "/v1/auth/password-reset/confirm", ["token", "new_password"]);
    expect(res.status).toBe(422);
    expect(await res.json()).toEqual({ detail: "Use at least 12 characters." });
    expect(JSON.parse((f.mock.calls[0]![1] as RequestInit).body as string)).toEqual({ token: "t", new_password: "short" });
    upstream(202, { detail: "If that address has an account, a link is on its way." });
    expect(await (await login.publicPost(req({ email: "a@b.test" }), "/v1/auth/password-reset", ["email"])).json()).toEqual({ ok: true, detail: "If that address has an account, a link is on its way." });
  });
});

describe("proxyRoute", () => {
  const get = (path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}, cookies = "app_session=TOK") =>
    new NextRequest(`http://app.test/api/bff/${path}`, { method: init.method ?? "GET", headers: { host: "app.test", origin: "http://app.test", cookie: cookies, ...(init.headers ?? {}) }, body: init.body });

  it("adds the token from the cookie, keeps to the allowed paths, and never reaches the sign-in routes", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ email: "a@b.test" }), { status: 200, headers: { "content-type": "application/json" } }));
    const ok = await login.proxyRoute(get("me"), ["me"]);
    expect(ok.status).toBe(200);
    const [url, init] = f.mock.calls[0]!;
    expect(String(url)).toBe("http://api.test/v1/me");
    expect(((init as RequestInit).headers as Record<string, string>).Authorization).toBe("Bearer TOK");
    for (const p of [["auth", "login"], ["platform", "settings"]]) expect((await login.proxyRoute(get(p.join("/")), p)).status).toBe(404);
    for (const p of [["me", ".."], ["me", "a%2Fb"], ["me", ""], []]) expect((await login.proxyRoute(get("x"), p)).status).toBe(400);
    expect((await login.proxyRoute(get("me"), ["me"], )).status).toBe(200);
    expect((await login.proxyRoute(get("me", {}, ""), ["me"])).status).toBe(401);
  });

  it("refuses a state-changing call from another site and passes a body through", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    expect((await login.proxyRoute(get("me/password", { method: "POST", headers: { origin: "http://evil.test" }, body: "{}" }), ["me", "password"])).status).toBe(403);
    const res = await login.proxyRoute(get("me/password", { method: "POST", headers: { "content-type": "application/json" }, body: '{"a":1}' }), ["me", "password"]);
    expect(res.status).toBe(204);
    expect((f.mock.calls[0]![1] as RequestInit).body).toBe('{"a":1}');
    expect((await login.proxyRoute(get("things", {}), ["things"], { allow: (p) => p === "things" })).status).toBe(204);
  });
});

describe("oidcStartRoute", () => {
  it("sends the browser to the provider, or back to the sign-in page when the provider cannot be reached", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify({ authorization_url: "https://idp.test/authorize?x=1" }), { status: 200 }));
    const r = await login.oidcStartRoute(new NextRequest("http://app.test/api/session/oidc/acme/start"), "acme");
    expect(r.headers.get("location")).toBe("https://idp.test/authorize?x=1");
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("{}", { status: 404 }));
    expect((await login.oidcStartRoute(new NextRequest("http://app.test/api/session/oidc/acme/start"), "acme")).headers.get("location")).toBe("http://app.test/login?error=provider");
    expect((await login.oidcStartRoute(new NextRequest("http://app.test/x"), "../evil")).status).toBe(404);
  });
});
