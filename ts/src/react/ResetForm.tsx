import { useState, type FormEvent } from "react";
import { Alert } from "./Alert";
import { useLogin } from "./context";

export function ResetForm({ token, minPasswordLength = 12 }: { token: string; minPasswordLength?: number }) {
  const { client, routes, classes } = useLogin();
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    const f = new FormData(e.currentTarget);
    if (f.get("password") !== f.get("again")) return setError("The two passwords are not the same.");
    const r = await client.publicCall("reset", { token, new_password: f.get("password") });
    if (!r.ok) return setError(r.error);
    setDone(true);
  }

  if (done)
    return (
      <>
        <Alert kind="success">Your password was changed and every device was signed out.</Alert>
        <p>
          <a href={routes.login}>Sign in</a>
        </p>
      </>
    );
  return (
    <form className={classes.stack} onSubmit={submit}>
      <Alert kind="error">{error}</Alert>
      <label>
        New password
        <input name="password" type="password" autoComplete="new-password" minLength={minPasswordLength} required />
        <span className={classes.hint}>{`At least ${minPasswordLength} characters.`}</span>
      </label>
      <label>
        Again
        <input name="again" type="password" autoComplete="new-password" minLength={minPasswordLength} required />
      </label>
      <button className={classes.primary}>Change password</button>
    </form>
  );
}
