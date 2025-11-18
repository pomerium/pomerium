/// <reference types="node" />
import type { BuildOptions} from "esbuild";
import { build, context } from "esbuild";

async function run() {
  const watching = process.argv.includes("--watch");

  const cfg: BuildOptions = {
    entryPoints: ["src/index.tsx"],
    bundle: true,
    outdir: "dist",
    sourcemap: watching ? "inline" : false,
    minify: !watching,
    logLevel: "info",
    loader: {
      ".svg": "dataurl",
      ".woff": "dataurl",
      ".woff2": "dataurl",
    },
  };

  if (watching) {
    await (await context(cfg)).watch();
  } else {
    await build(cfg);
  }
}

run();
