import { useState, type FormEvent } from "react";
import { Alert } from "./Alert";
import { useLogin } from "./context";

export function ForgotForm({ validity = "an hour" }: { validity?: string }) {
  const { client, routes, classes, Link } = useLogin();
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    const r = await client.publicCall("forgot", { email: new FormData(e.currentTarget).get("email") });
    if (!r.ok) return setError(r.error);
    setDone(true);
  }

  if (done)
    return (
      <>
        <Alert kind="success">{`If that address has an account, we have sent a link to reset the password. It is valid for ${validity}.`}</Alert>
        <p>
          <Link href={routes.login}>Back to sign in</Link>
        </p>
      </>
    );
  return (
    <form className={classes.stack} onSubmit={submit}>
      <Alert kind="error">{error}</Alert>
      <label>
        Email
        <input name="email" type="email" autoComplete="username" required />
      </label>
      <button className={classes.primary}>Send reset link</button>
      <p>
        <Link href={routes.login}>Back to sign in</Link>
      </p>
    </form>
  );
}
