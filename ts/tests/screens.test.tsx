// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Client, Result } from "../src/index";
import { ForgotForm, LoginForm, LoginProvider, OidcCallback, RegisterForm, ResendVerification, ResetForm, SecurityPanel, VerifyEmail } from "../src/react";

const ok = <T,>(data: T): Result<T> => ({ ok: true, status: 200, data, error: "" });
const fail = (error: string, status = 400): Result<never> => ({ ok: false, status, data: null as never, error });

function fake(over: Partial<Client> = {}) {
  const client = {
    session: vi.fn(async () => ok({ next: "done" })),
    call: vi.fn(async () => ok({})),
    publicCall: vi.fn(async () => ok({ ok: true, detail: "" })),
    ...over,
  } as unknown as Client & { session: ReturnType<typeof vi.fn>; call: ReturnType<typeof vi.fn>; publicCall: ReturnType<typeof vi.fn> };
  const navigate = vi.fn();
  const wrap = (ui: React.ReactElement) => render(<LoginProvider client={client} navigate={navigate}>{ui}</LoginProvider>);
  return { client, navigate, wrap };
}

const opts = { local_login: true, registration_open: true, providers: [{ key: "acme", name: "Acme SSO" }] };

afterEach(cleanup);

describe("LoginForm", () => {
  it("signs in with a password and goes where it was asked to", async () => {
    const { client, navigate, wrap } = fake();
    wrap(<LoginForm {...opts} next="/dash" />);
    await userEvent.type(screen.getByLabelText("Email"), "a@b.test");
    await userEvent.type(screen.getByLabelText("Password"), "pw pw pw pw pw");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(client.session).toHaveBeenCalledWith("login", { email: "a@b.test", password: "pw pw pw pw pw" });
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dash"));
  });

  it("asks for the code after the password, can switch to a recovery code, and starts over when the challenge is gone", async () => {
    const session = vi.fn()
      .mockResolvedValueOnce(ok({ next: "mfa" }))
      .mockResolvedValueOnce(fail("Sign in again.", 401))
      .mockResolvedValueOnce(ok({ next: "mfa" }))
      .mockResolvedValueOnce(ok({ next: "done" }));
    const { client, navigate, wrap } = fake({ session } as unknown as Partial<Client>);
    wrap(<LoginForm {...opts} />);
    await userEvent.type(screen.getByLabelText("Email"), "a@b.test");
    await userEvent.type(screen.getByLabelText("Password"), "pw");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByLabelText("Code from your authenticator app")).toBeTruthy();
    await userEvent.type(screen.getByLabelText("Code from your authenticator app"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(session).toHaveBeenLastCalledWith("mfa", { code: "123456" });
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Sign in again."); // back to the password step
    expect(screen.getByLabelText("Password")).toBeTruthy();
    await userEvent.type(screen.getByLabelText("Email"), "a@b.test");
    await userEvent.type(screen.getByLabelText("Password"), "pw");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await userEvent.click(await screen.findByRole("button", { name: "Use a recovery code" }));
    await userEvent.type(screen.getByLabelText("Recovery code"), "abcde-fghjk");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(session).toHaveBeenLastCalledWith("mfa", { recovery_code: "abcde-fghjk" });
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/"));
    expect(client.session).toBe(session);
  });

  it("sends a person who owes a second factor or a confirmed email to the right page", async () => {
    for (const [next, to] of [["enrol", "/account/security"], ["verify", "/account/verify"]] as const) {
      const { navigate, wrap } = fake({ session: vi.fn(async () => ok({ next })) } as unknown as Partial<Client>);
      wrap(<LoginForm {...opts} />);
      await userEvent.type(screen.getByLabelText("Email"), "a@b.test");
      await userEvent.type(screen.getByLabelText("Password"), "pw");
      await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
      await waitFor(() => expect(navigate).toHaveBeenCalledWith(to));
      cleanup();
    }
  });

  it("shows a server refusal and offers single sign-on, forgot-password and sign-up links", async () => {
    const { wrap } = fake({ session: vi.fn(async () => fail("Email or password is not right.", 401)) } as unknown as Partial<Client>);
    wrap(<LoginForm {...opts} providerError />);
    expect(screen.getByRole("alert").textContent).toMatch(/not available/);
    expect(screen.getByRole("link", { name: "Continue with Acme SSO" }).getAttribute("href")).toBe("/api/session/oidc/acme/start");
    expect(screen.getByRole("link", { name: "Forgot your password?" }).getAttribute("href")).toBe("/forgot-password");
    expect(screen.getByRole("link", { name: "Create an account" }).getAttribute("href")).toBe("/register");
    await userEvent.type(screen.getByLabelText("Email"), "a@b.test");
    await userEvent.type(screen.getByLabelText("Password"), "x");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Email or password is not right."));
  });

  it("offers only what the server allows", () => {
    const { wrap } = fake();
    wrap(<LoginForm local_login={false} registration_open providers={[]} />);
    expect(screen.queryByLabelText("Password")).toBeNull();
    expect(screen.queryByRole("link", { name: "Create an account" })).toBeNull();
    expect(screen.getByRole("alert").textContent).toMatch(/Sign-in is not available/);
    cleanup();
    wrap(<LoginForm local_login registration_open={false} providers={[]} />);
    expect(screen.queryByRole("link", { name: "Create an account" })).toBeNull();
  });
});

describe("RegisterForm", () => {
  it("sends the fields plus whatever the app adds, then follows the server's next step", async () => {
    const { client, navigate, wrap } = fake({ session: vi.fn(async () => ok({ next: "verify" })) } as unknown as Partial<Client>);
    wrap(<RegisterForm extraFields={<input name="company" aria-label="Company" />} extraBody={(f) => ({ company_name: f.get("company") || null })} />);
    await userEvent.type(screen.getByLabelText("Your name"), "Pat");
    await userEvent.type(screen.getByLabelText("Email"), "pat@example.test");
    await userEvent.type(screen.getByLabelText(/^Password/), "a long enough passphrase");
    await userEvent.type(screen.getByLabelText("Company"), "Acme");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(client.session).toHaveBeenCalledWith("register", { name: "Pat", email: "pat@example.test", password: "a long enough passphrase", company_name: "Acme" });
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/account/verify"));
  });
});

describe("password reset and email confirmation", () => {
  it("asks for a link without saying whether the address exists", async () => {
    const { client, wrap } = fake();
    wrap(<ForgotForm />);
    await userEvent.type(screen.getByLabelText("Email"), "a@b.test");
    await userEvent.click(screen.getByRole("button", { name: "Send reset link" }));
    expect(client.publicCall).toHaveBeenCalledWith("forgot", { email: "a@b.test" });
    expect((await screen.findByRole("status")).textContent).toMatch(/If that address has an account/);
  });

  it("checks the two passwords match before asking the server", async () => {
    const { client, wrap } = fake();
    wrap(<ResetForm token="tok" />);
    await userEvent.type(screen.getByLabelText(/^New password/), "a long enough passphrase");
    await userEvent.type(screen.getByLabelText("Again"), "something different entirely");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect((await screen.findByRole("alert")).textContent).toBe("The two passwords are not the same.");
    expect(client.publicCall).not.toHaveBeenCalled();
    await userEvent.clear(screen.getByLabelText("Again"));
    await userEvent.type(screen.getByLabelText("Again"), "a long enough passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(client.publicCall).toHaveBeenCalledWith("reset", { token: "tok", new_password: "a long enough passphrase" });
    expect((await screen.findByRole("status")).textContent).toMatch(/every device was signed out/);
  });

  it("uses the one-time confirmation link once, and clears it from the address bar", async () => {
    window.history.replaceState(null, "", "/verify-email?token=SECRET");
    const { client, wrap } = fake();
    wrap(<VerifyEmail token="SECRET" />);
    expect((await screen.findByRole("status")).textContent).toMatch(/confirmed/);
    expect(client.publicCall).toHaveBeenCalledTimes(1);
    expect(window.location.search).toBe("");
  });

  it("can send the confirmation link again", async () => {
    const { client, wrap } = fake();
    wrap(<ResendVerification />);
    await userEvent.click(screen.getByRole("button", { name: "Send the link again" }));
    expect(client.call).toHaveBeenCalledWith("POST", "me/verify-email/resend");
    expect((await screen.findByRole("status")).textContent).toMatch(/Sent/);
  });
});

describe("OidcCallback", () => {
  beforeEach(() => window.history.replaceState(null, "", "/auth/callback/acme?code=CODE&state=STATE"));

  it("finishes the sign-in once and removes the code from the address bar first", async () => {
    const { client, navigate, wrap } = fake();
    wrap(<OidcCallback providerKey="acme" />);
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/"));
    expect(client.session).toHaveBeenCalledTimes(1);
    expect(client.session).toHaveBeenCalledWith("oidc/acme", { code: "CODE", state: "STATE" });
    expect(window.location.search).toBe("");
  });

  it("says so when the provider sent nothing, or the server refuses", async () => {
    window.history.replaceState(null, "", "/auth/callback/acme");
    const a = fake();
    a.wrap(<OidcCallback providerKey="acme" />);
    expect((await screen.findByRole("alert")).textContent).toMatch(/did not complete/);
    cleanup();
    window.history.replaceState(null, "", "/auth/callback/acme?code=C&state=S");
    const b = fake({ session: vi.fn(async () => fail("The sign-in expired. Start again.", 401)) } as unknown as Partial<Client>);
    b.wrap(<OidcCallback providerKey="acme" />);
    expect((await screen.findByRole("alert")).textContent).toBe("The sign-in expired. Start again.");
    expect(screen.getByRole("link", { name: "Back to sign in" }).getAttribute("href")).toBe("/login");
  });
});

describe("SecurityPanel", () => {
  it("sets up the authenticator and shows recovery codes once", async () => {
    const call = vi.fn()
      .mockResolvedValueOnce(ok({ secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://x" }))
      .mockResolvedValueOnce(ok({ recovery_codes: ["aaaaa-bbbbb", "ccccc-ddddd"] }));
    const { wrap } = fake({ call } as unknown as Partial<Client>);
    wrap(<SecurityPanel mfaEnabled={false} />);
    await userEvent.click(screen.getByRole("button", { name: "Set up" }));
    expect(await screen.findByText("JBSWY3DPEHPK3PXP")).toBeTruthy();
    await userEvent.type(screen.getByLabelText(/6-digit code/), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Turn on" }));
    expect(call).toHaveBeenLastCalledWith("POST", "me/mfa/totp/confirm", { code: "123456" });
    expect(await screen.findByText("aaaaa-bbbbb")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "I have saved them" }));
    expect(screen.queryByText("aaaaa-bbbbb")).toBeNull();
    expect(screen.getByText("On")).toBeTruthy();
  });

  it("a limited session can enrol but not change the password or remove the factor, and continues home afterwards", async () => {
    const call = vi.fn().mockResolvedValueOnce(ok({ secret: "S", otpauth_uri: "u" })).mockResolvedValueOnce(ok({ recovery_codes: ["x-y"] }));
    const { navigate, wrap } = fake({ call } as unknown as Partial<Client>);
    wrap(<SecurityPanel mfaEnabled={false} limited />);
    expect(screen.queryByText("Change password")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Set up" }));
    await userEvent.type(await screen.findByLabelText(/6-digit code/), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Turn on" }));
    await userEvent.click(await screen.findByRole("button", { name: "I have saved them, continue" }));
    expect(navigate).toHaveBeenCalledWith("/");
    expect(screen.queryByRole("button", { name: "Remove second factor" })).toBeNull();
  });

  it("removes the factor with the password and changes the password", async () => {
    const call = vi.fn(async () => ok({}));
    const { wrap } = fake({ call } as unknown as Partial<Client>);
    wrap(<SecurityPanel mfaEnabled />);
    await userEvent.type(screen.getAllByLabelText("Password")[0]!, "my current password");
    await userEvent.click(screen.getByRole("button", { name: "Remove second factor" }));
    expect(call).toHaveBeenCalledWith("DELETE", "me/mfa", { password: "my current password" });
    await userEvent.type(screen.getByLabelText("Current password"), "old password here");
    await userEvent.type(screen.getByLabelText(/^New password/), "a brand new passphrase");
    await userEvent.click(screen.getAllByRole("button", { name: "Change password" })[0]!);
    expect(call).toHaveBeenLastCalledWith("POST", "me/password", { current_password: "old password here", new_password: "a brand new passphrase" });
  });
});

describe("styling hooks", () => {
  it("uses the class names it is given", () => {
    const { client } = fake();
    render(<LoginProvider client={client} classes={{ primary: "btn-main", stack: "vstack" }}><LoginForm {...opts} /></LoginProvider>);
    expect(screen.getByRole("button", { name: "Sign in" }).className).toBe("btn-main");
    expect(document.querySelector("form")!.className).toBe("vstack");
  });
});
