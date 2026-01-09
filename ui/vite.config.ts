import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  base: "/.pomerium/",
  build: {
    assetsInlineLimit: 1024 * 1024 * 1024,
    rollupOptions: {
      output: {
        assetFileNames: "[name][extname]",
        entryFileNames: "[name].js",
        chunkFileNames: "[name].js",
        manualChunks: () => "index",
      },
    },
  },
});
