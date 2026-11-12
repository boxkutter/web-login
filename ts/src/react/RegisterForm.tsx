import { useState, type FormEvent, type ReactNode } from "react";
import { destination } from "../index";
import { Alert } from "./Alert";
import { useLogin } from "./context";

export interface RegisterFormProps {
  /** Extra fields for your own sign-up (a company name, a consent box...). */
  extraFields?: ReactNode;
  /** Extra values to send, read from the form. Return only what your server's sign-up accepts. */
  extraBody?: (form: FormData) => Record<string, unknown>;
  /** Where to go when sign-up is complete (default: home). */
  redirectTo?: string;
  /** Hint under the password field. */
  passwordHint?: string;
  minPasswordLength?: number;
}

export function RegisterForm({ extraFields, extraBody, redirectTo, passwordHint = "At least 12 characters. A few words together make a strong password.", minPasswordLength = 12 }: RegisterFormProps) {
  const { client, routes, classes, navigate } = useLogin();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const f = new FormData(e.currentTarget);
    const r = await client.session("register", { name: f.get("name"), email: f.get("email"), password: f.get("password"), ...(extraBody ? extraBody(f) : {}) });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    navigate(destination(r.data.next, routes, redirectTo ?? routes.home));
  }

  return (
    <form className={classes.stack} onSubmit={submit}>
      <Alert kind="error">{error}</Alert>
      <label>
        Your name
        <input name="name" type="text" autoComplete="name" required />
      </label>
      <label>
        Email
        <input name="email" type="email" autoComplete="username" required />
      </label>
      <label>
        Password
        <input name="password" type="password" autoComplete="new-password" minLength={minPasswordLength} required />
        <span className={classes.hint}>{passwordHint}</span>
      </label>
      {extraFields}
      <button className={classes.primary} disabled={busy}>
        Create account
      </button>
    </form>
  );
}
