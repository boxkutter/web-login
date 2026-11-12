import { useState, type FormEvent } from "react";
import { destination, type Options } from "../index";
import { Alert } from "./Alert";
import { useLogin } from "./context";

export interface LoginFormProps extends Options {
  /** Where to go after signing in (already checked with `safeNext`). */
  next?: string;
  /** Show "that sign-in method is not available" (the provider flow sent the person back with an error). */
  providerError?: boolean;
  /** Hide the "Create an account" link even when registration is open. */
  hideRegister?: boolean;
}

export function LoginForm({ local_login: localLogin, providers, registration_open: registrationOpen, next = "/", providerError, hideRegister }: LoginFormProps) {
  const { client, routes, classes, Link, navigate } = useLogin();
  const [step, setStep] = useState<"password" | "mfa">("password");
  const [error, setError] = useState(providerError ? "That sign-in method is not available right now." : "");
  const [busy, setBusy] = useState(false);
  const [useRecovery, setUseRecovery] = useState(false);

  function go(result: string) {
    if (result === "mfa") return setStep("mfa");
    navigate(destination(result, routes, next));
  }

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const f = new FormData(e.currentTarget);
    const r =
      step === "password"
        ? await client.session("login", { email: f.get("email"), password: f.get("password") })
        : await client.session("mfa", useRecovery ? { recovery_code: f.get("code") } : { code: f.get("code") });
    setBusy(false);
    if (!r.ok) {
      if (step === "mfa" && r.status === 401 && /sign in again/i.test(r.error)) setStep("password");
      return setError(r.error);
    }
    go(r.data.next);
  }

  return (
    <>
      <Alert kind="error">{error}</Alert>
      {localLogin && step === "password" ? (
        <form className={classes.stack} onSubmit={submit}>
          <label>
            Email
            <input name="email" type="email" autoComplete="username" required />
          </label>
          <label>
            Password
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button className={classes.primary} disabled={busy}>
            Sign in
          </button>
        </form>
      ) : null}
      {step === "mfa" ? (
        <form className={classes.stack} onSubmit={submit}>
          <label>
            {useRecovery ? "Recovery code" : "Code from your authenticator app"}
            <input name="code" type="text" inputMode={useRecovery ? "text" : "numeric"} autoComplete="one-time-code" required autoFocus />
          </label>
          <button className={classes.primary} disabled={busy}>
            Continue
          </button>
          <button type="button" onClick={() => setUseRecovery(!useRecovery)}>
            {useRecovery ? "Use the authenticator app instead" : "Use a recovery code"}
          </button>
        </form>
      ) : null}
      {step === "password" && providers.length > 0 ? (
        <>
          {localLogin ? <p className={classes.divider}>or</p> : null}
          <div className={classes.stack}>
            {providers.map((p) => (
              <a key={p.key} className={classes.button} href={routes.oidcStart(p.key)}>
                Continue with {p.name}
              </a>
            ))}
          </div>
        </>
      ) : null}
      {!localLogin && providers.length === 0 ? <Alert kind="error">Sign-in is not available. Contact your administrator.</Alert> : null}
      {localLogin && step === "password" ? (
        <p>
          <Link href={routes.forgot}>Forgot your password?</Link>
        </p>
      ) : null}
      {localLogin && registrationOpen && !hideRegister && step === "password" ? (
        <p>
          New here? <Link href={routes.register}>Create an account</Link>
        </p>
      ) : null}
    </>
  );
}
