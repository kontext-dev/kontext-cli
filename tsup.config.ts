import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/bin.ts"],
  format: ["esm"],
  outExtension: () => ({ js: ".mjs" }),
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: false,
  banner: {
    js: "#!/usr/bin/env node",
  },
});
