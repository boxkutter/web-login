import { useEffect, useRef, useState } from "react";
import { Alert } from "./Alert";
import { useLogin } from "./context";

/** The provider sent the person back with ?code=…&state=…; the server finishes the sign-in. */
export function OidcCallback({ providerKey, redirectTo }: { providerKey: string; redirectTo?: string }) {
  const { client, routes, navigate } = useLogin();
  const [error, setError] = useState("");
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return; // the authorisation code is single use
    done.current = true;
    const q = new URLSearchParams(window.location.search);
    const code = q.get("code");
    const state = q.get("state");
    if (!code || !state) return setError("The sign-in did not complete.");
    // The code and state are in the address bar: clear them before anything else.
    window.history.replaceState(null, "", window.location.pathname);
    client.session(`oidc/${encodeURIComponent(providerKey)}`, { code, state }).then((r) => {
      if (r.ok) navigate(redirectTo ?? routes.home);
      else setError(r.error);
    });
  }, [providerKey, client, navigate, redirectTo, routes.home]);

  return (
    <>
      <Alert kind="error">{error}</Alert>
      {error ? <a href={routes.login}>Back to sign in</a> : <p>One moment.</p>}
    </>
  );
}
