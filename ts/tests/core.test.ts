import { describe, expect, it, vi } from "vitest";
import { createClient, destination, DEFAULT_ROUTES, nextForState, safeNext } from "../src/index";

describe("safeNext", () => {
  it("keeps same-site paths and refuses anything that could leave the site", () => {
    expect(safeNext("/dashboard?tab=1")).toBe("/dashboard?tab=1");
    for (const bad of ["//evil.test", "https://evil.test", "/\\evil", "javascript:alert(1)", "", undefined, null, "/a b"]) expect(safeNext(bad as string)).toBe("/");
    expect(safeNext("//x", "/home")).toBe("/home");
  });
});

describe("states", () => {
  it("maps the server's session state to the next step", () => {
    expect(nextForState("full")).toBe("done");
    expect(nextForState("mfa_pending")).toBe("mfa");
    expect(nextForState("mfa_enrol")).toBe("enrol");
    expect(nextForState("verify_email")).toBe("verify");
    expect(destination("enrol", DEFAULT_ROUTES, "/x")).toBe("/account/security");
    expect(destination("done", DEFAULT_ROUTES, "/x")).toBe("/x");
  });
});

describe("client", () => {
  const reply = (status: number, body: unknown) => vi.fn(async () => new Response(body === null ? null : JSON.stringify(body), { status }));

  it("posts JSON to the right place and reads problem details", async () => {
    const f = reply(401, { detail: "Email or password is not right." });
    const c = createClient({}, f as unknown as typeof fetch);
    const r = await c.session("login", { email: "a@b.test", password: "x" });
    expect(r).toMatchObject({ ok: false, status: 401, error: "Email or password is not right." });
    expect(f).toHaveBeenCalledWith("/api/session/login", expect.objectContaining({ method: "POST", body: JSON.stringify({ email: "a@b.test", password: "x" }) }));
  });

  it("prefers the first field error, copes with 204 and with a service that is down", async () => {
    const c1 = createClient({}, reply(422, { errors: [{ msg: "Too short." }], detail: "x" }) as unknown as typeof fetch);
    expect((await c1.call("POST", "me/password", {})).error).toBe("Too short.");
    const c2 = createClient({ api: "/proxy" }, reply(204, null) as unknown as typeof fetch);
    expect(await c2.call("DELETE", "me/mfa", { password: "p" })).toMatchObject({ ok: true, data: null });
    const down = createClient({}, vi.fn(async () => { throw new Error("offline"); }) as unknown as typeof fetch);
    expect((await down.publicCall("forgot", {})).error).toMatch(/not reachable/);
  });
});
