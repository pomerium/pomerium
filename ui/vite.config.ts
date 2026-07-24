import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig(({ mode }) => {
  const dev = mode === "development";

  return {
    plugins: [react()],
    build: {
      outDir: "dist",
      // We deliberately emit a single iife bundle (see rolldownOptions), so the
      // chunk-size warning isn't actionable. Disable it (nothing exceeds Infinity).
      chunkSizeWarningLimit: Infinity,
      // Don't wipe dist/: it also holds the checked-in index.gohtml and favicons.
      emptyOutDir: false,
      // Emit a single index.css instead of per-chunk stylesheets.
      cssCodeSplit: false,
      // Inline every referenced asset (svgs, woff/woff2 fonts) as a data URL so
      // the output stays to just index.js and index.css.
      assetsInlineLimit: () => true,
      sourcemap: dev ? "inline" : false,
      minify: !dev,
      rolldownOptions: {
        input: "src/index.tsx",
        // output a single js file for everything
        output: {
          format: "iife",
          entryFileNames: "index.js",
          assetFileNames: (asset) =>
            asset.names.some((name) => name.endsWith(".css"))
              ? "index.css"
              : "[name][extname]",
        },
      },
    },
  };
});
