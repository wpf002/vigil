/* ESLint config — Vite + React + TypeScript.
 * Matches the deps already in package.json; nothing new required. */
module.exports = {
  root: true,
  env: { browser: true, es2022: true },
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react-hooks/recommended",
  ],
  ignorePatterns: ["dist", ".eslintrc.cjs", "node_modules", "vite.config.ts", "tailwind.config.js", "postcss.config.js"],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
    ecmaFeatures: { jsx: true },
  },
  plugins: ["react-refresh", "@typescript-eslint"],
  rules: {
    "react-refresh/only-export-components": [
      "warn",
      { allowConstantExport: true },
    ],
    // TS already enforces no-unused-vars via noUnusedLocals/Parameters; keep
    // the eslint version off to avoid duplicate diagnostics.
    "no-unused-vars": "off",
    "@typescript-eslint/no-unused-vars": [
      "warn",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
    ],
    // Prefer explicit any over the rule's default which fires on lots of
    // legitimate situations (event handlers, third-party stubs).
    "@typescript-eslint/no-explicit-any": "off",
  },
};
