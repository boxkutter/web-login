import { useState, type FormEvent } from "react";
import { Alert } from "./Alert";
import { useLogin } from "./context";

export interface SecurityPanelProps {
  mfaEnabled: boolean;
  /** The session is limited (a second factor is required and not set up yet): no password change or removal here. */
  limited?: boolean;
  minPasswordLength?: number;
}

/** Authenticator app set-up, recovery codes, and changing the password. */
export function SecurityPanel({ mfaEnabled, limited = false, minPasswordLength = 12 }: SecurityPanelProps) {
  const { client, routes, classes, navigate } = useLogin();
  const [enabled, setEnabled] = useState(mfaEnabled);
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function begin() {
    setError("");
    const r = await client.call<{ secret: string; otpauth_uri: string }>("POST", "me/mfa/totp/setup");
    if (!r.ok) return setError(r.error);
    setSetup(r.data);
  }

  async function confirm(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    const r = await client.call<{ recovery_codes: string[] }>("POST", "me/mfa/totp/confirm", { code: new FormData(e.currentTarget).get("code") });
    if (!r.ok) return setError(r.error);
    setSetup(null);
    setCodes(r.data.recovery_codes);
    setEnabled(true);
  }

  async function newCodes() {
    setError("");
    const r = await client.call<{ recovery_codes: string[] }>("POST", "me/mfa/recovery-codes");
    if (!r.ok) return setError(r.error);
    setCodes(r.data.recovery_codes);
  }

  async function remove(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    const r = await client.call("DELETE", "me/mfa", { password: new FormData(e.currentTarget).get("password") });
    if (!r.ok) return setError(r.error);
    setEnabled(false);
    setNotice("Second factor removed.");
  }

  async function changePassword(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setNotice("");
    const form = e.currentTarget;
    const f = new FormData(form);
    const r = await client.call("POST", "me/password", { current_password: f.get("current"), new_password: f.get("next") });
    if (!r.ok) return setError(r.error);
    form.reset();
    setNotice("Password changed. Other devices have been signed out.");
  }

  return (
    <>
      <Alert kind="error">{error}</Alert>
      <Alert kind="success">{notice}</Alert>

      <section className={classes.card} aria-labelledby="wl-mfa-h">
        <h2 id="wl-mfa-h" style={{ marginTop: 0 }}>
          Authenticator app {enabled ? <span className={classes.badgeOn}>On</span> : <span className={classes.badge}>Off</span>}
        </h2>
        {codes ? (
          <div>
            <p>
              <strong>Save these recovery codes now.</strong> Each works once if you lose your phone. They will not be shown again.
            </p>
            <ol className={classes.codes}>
              {codes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ol>
            <button onClick={() => (limited ? navigate(routes.home) : setCodes(null))}>{limited ? "I have saved them, continue" : "I have saved them"}</button>
          </div>
        ) : setup ? (
          <form className={classes.stack} onSubmit={confirm}>
            <p>In your authenticator app add an account with this key (choose &ldquo;enter a setup key&rdquo;, time-based):</p>
            <p>
              <code>{setup.secret}</code>
            </p>
            <label>
              Then enter the 6-digit code it shows
              <input name="code" type="text" inputMode="numeric" autoComplete="one-time-code" required />
            </label>
            <div className={classes.row}>
              <button className={classes.primary}>Turn on</button>
              <button type="button" onClick={() => setSetup(null)}>
                Cancel
              </button>
            </div>
          </form>
        ) : enabled ? (
          <div className={classes.stack}>
            <p>A code from your app is asked for each time you sign in with your password.</p>
            <div className={classes.row}>
              <button onClick={newCodes}>Get new recovery codes</button>
            </div>
            {!limited ? (
              <form className={classes.stack} onSubmit={remove}>
                <label>
                  Password
                  <input name="password" type="password" autoComplete="current-password" required />
                </label>
                <button className={classes.danger}>Remove second factor</button>
              </form>
            ) : null}
          </div>
        ) : (
          <>
            <p>Adds a one-time code from an app such as Aegis, 1Password or Google Authenticator to signing in.</p>
            <button className={classes.primary} onClick={begin}>
              Set up
            </button>
          </>
        )}
      </section>

      {!limited ? (
        <section className={classes.card} aria-labelledby="wl-pw-h">
          <h2 id="wl-pw-h" style={{ marginTop: 0 }}>
            Change password
          </h2>
          <form className={classes.stack} onSubmit={changePassword} style={{ maxWidth: "24rem" }}>
            <label>
              Current password
              <input name="current" type="password" autoComplete="current-password" required />
            </label>
            <label>
              New password
              <input name="next" type="password" autoComplete="new-password" minLength={minPasswordLength} required />
              <span className={classes.hint}>{`At least ${minPasswordLength} characters.`}</span>
            </label>
            <button className={classes.primary}>Change password</button>
          </form>
        </section>
      ) : null}
    </>
  );
}
