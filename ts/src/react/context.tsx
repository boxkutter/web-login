import { createContext, useContext, useMemo, type AnchorHTMLAttributes, type ComponentType, type ReactNode } from "react";
import { createClient, DEFAULT_PATHS, DEFAULT_ROUTES, type Client, type ClientPaths, type Routes } from "../index";

/** Class names the screens use. Defaults suit the stylesheet shipped as "@boxkutter/web-login/styles.css"; replace any of them to match your own. */
export interface Classes {
  stack: string;
  row: string;
  primary: string;
  danger: string;
  button: string;
  hint: string;
  card: string;
  badge: string;
  badgeOn: string;
  divider: string;
  codes: string;
  alertError: string;
  alertSuccess: string;
}

export const DEFAULT_CLASSES: Classes = {
  stack: "stack",
  row: "row",
  primary: "primary",
  danger: "danger",
  button: "button",
  hint: "hint",
  card: "card",
  badge: "badge",
  badgeOn: "badge badge--on",
  divider: "divider",
  codes: "codes",
  alertError: "alert alert--error",
  alertSuccess: "alert alert--success",
};

export type LinkLike = ComponentType<AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }>;

const PlainLink: LinkLike = ({ href, children, ...rest }) => (
  <a href={href} {...rest}>
    {children}
  </a>
);

export interface LoginContext {
  client: Client;
  routes: Routes;
  classes: Classes;
  /** The element used for links between sign-in pages; give your router's Link (for example Next's) for client-side navigation. */
  Link: LinkLike;
  /** Where the browser is sent (override in tests). */
  navigate: (href: string) => void;
}

const defaults: LoginContext = {
  client: createClient(),
  routes: DEFAULT_ROUTES,
  classes: DEFAULT_CLASSES,
  Link: PlainLink,
  navigate: (href) => {
    window.location.href = href;
  },
};

const Ctx = createContext<LoginContext>(defaults);

export interface LoginProviderProps {
  children: ReactNode;
  paths?: Partial<ClientPaths>;
  routes?: Partial<Routes>;
  classes?: Partial<Classes>;
  Link?: LinkLike;
  client?: Client;
  navigate?: (href: string) => void;
}

export function LoginProvider({ children, paths, routes, classes, Link, client, navigate }: LoginProviderProps) {
  const value = useMemo<LoginContext>(
    () => ({
      client: client ?? createClient({ ...DEFAULT_PATHS, ...paths }),
      routes: { ...DEFAULT_ROUTES, ...routes },
      classes: { ...DEFAULT_CLASSES, ...classes },
      Link: Link ?? PlainLink,
      navigate: navigate ?? defaults.navigate,
    }),
    [paths, routes, classes, Link, client, navigate],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useLogin = () => useContext(Ctx);
