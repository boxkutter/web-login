import { defineConfig } from "tsup";

const external = ["react", "react-dom", "react/jsx-runtime", "next", /^next\//];

export default defineConfig([
  { entry: { index: "src/index.ts" }, format: ["esm", "cjs"], dts: true, clean: true, sourcemap: true, external },
  // the screens are client components: the directive must lead the bundle
  { entry: { react: "src/react/index.ts" }, format: ["esm", "cjs"], dts: true, sourcemap: true, external, banner: { js: '"use client";' }, esbuildOptions: (o) => { o.jsx = "automatic"; } },
  { entry: { server: "src/server/index.ts" }, format: ["esm", "cjs"], dts: true, sourcemap: true, external },
]);
