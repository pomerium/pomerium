/// <reference types="node" />
import { BuildOptions, build, context } from "esbuild";

async function run() {
  const cfg: BuildOptions = {
    entryPoints: ["src/index.tsx"],
    bundle: true,
    outdir: "dist",
    sourcemap: "linked",
    minify: !process.argv.includes("--watch"),
    logLevel: "info",
    loader: {
      ".svg": "dataurl",
      ".woff": "dataurl",
      ".woff2": "dataurl",
    },
  };

  if (process.argv.includes("--watch")) {
    await (await context(cfg)).watch();
  } else {
    await build(cfg);
  }
}

run();
