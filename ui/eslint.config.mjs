import js from "@eslint/js";
import eslintReact from "@eslint-react/eslint-plugin";
import globals from "globals";
import tseslint from "typescript-eslint";

export default [
  // Global ignores
  {
    ignores: ["dist/**", "node_modules/**", "*.go"],
  },

  // JS/TS files
  {
    files: ["**/*.{js,mjs,cjs,ts,mts,cts,jsx,tsx}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node, // for scripts/esbuild.ts
      },
    },
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  // React rules via @eslint-react (eslint 10+, flat-config native).
  // Replaces eslint-plugin-react, which has no eslint 10 release.
  {
    files: ["**/*.{js,mjs,cjs,jsx,ts,mts,cts,tsx}"],
    ...eslintReact.configs["recommended-typescript"],
  },

  {
    rules: {
      "@typescript-eslint/consistent-type-imports": [
        "error",
        {
          prefer: "type-imports",
          disallowTypeAnnotations: true,
          fixStyle: "separate-type-imports",
        },
      ],
      // Add other rule overrides as needed
    },
  },
];
