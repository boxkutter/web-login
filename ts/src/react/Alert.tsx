import type { ReactNode } from "react";
import { useLogin } from "./context";

/** Status messages announced to assistive technology: errors assertively, successes politely. */
export function Alert({ kind, children }: { kind: "error" | "success"; children: ReactNode }) {
  const { classes } = useLogin();
  if (!children) return null;
  return (
    <div className={kind === "error" ? classes.alertError : classes.alertSuccess} role={kind === "error" ? "alert" : "status"}>
      {children}
    </div>
  );
}
