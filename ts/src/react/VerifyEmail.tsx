import { useEffect, useRef, useState } from "react";
import { Alert } from "./Alert";
import { useLogin } from "./context";

/** The link is opened in a browser: confirm once (the token is single use), then move on. */
export function VerifyEmail({ token, continueLabel = "Continue" }: { token: string; continueLabel?: string }) {
  const { client, routes } = useLogin();
  const [state, setState] = useState<"working" | "ok" | "error">("working");
  const [error, setError] = useState("");
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return;
    done.current = true;
    window.history.replaceState(null, "", window.location.pathname);
    client.publicCall("verify", { token }).then((r) => {
      if (r.ok) setState("ok");
      else {
        setError(r.error);
        setState("error");
      }
    });
  }, [token, client]);

  return (
    <>
      {state === "ok" ? <Alert kind="success">Your email address is confirmed.</Alert> : null}
      {state === "error" ? <Alert kind="error">{error}</Alert> : null}
      {state !== "working" ? (
        <p>
          <a href={routes.home}>{continueLabel}</a>
        </p>
      ) : (
        <p>One moment.</p>
      )}
    </>
  );
}
