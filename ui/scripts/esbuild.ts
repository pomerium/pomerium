import { build } from "esbuild";

build({
  entryPoints: ["src/index.tsx"],
  bundle: true,
  outfile: "dist/index.js",
  sourcemap: "inline",
  watch: process.argv.includes("--watch"),
  minify: !process.argv.includes("--watch"),
  logLevel: "info",
  loader: {
    ".svg": "dataurl",
    ".woff": "dataurl",
    ".woff2": "dataurl",
  },
});
