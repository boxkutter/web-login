import { useState } from "react";
import { Alert } from "./Alert";
import { useLogin } from "./context";

export function ResendVerification() {
  const { client } = useLogin();
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  async function again() {
    setMsg("");
    setError("");
    const r = await client.call("POST", "me/verify-email/resend");
    if (r.ok) setMsg("Sent. Check your inbox (and spam folder).");
    else setError(r.error);
  }

  return (
    <>
      <Alert kind="success">{msg}</Alert>
      <Alert kind="error">{error}</Alert>
      <button onClick={again}>Send the link again</button>
    </>
  );
}
