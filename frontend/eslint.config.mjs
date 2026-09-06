// Flat config. The rules that matter here are the ones the threat model names, not style:
// style is settled by the formatter and by review.
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "next-env.d.ts",
      "coverage/**",
      "playwright-report/**",
      "test-results/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
  },
  {
    files: ["**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // T-1.3: stored XSS from log content. Every string this dashboard renders came from a
      // packet somebody else sent — a DNS query name, an HTTP host, a Suricata signature. React
      // escapes text nodes, and this is the one escape hatch that would undo that. There is no
      // legitimate use of it in this codebase: note bodies go through SafeMarkdown, which
      // builds elements rather than HTML.
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message:
            "dangerouslySetInnerHTML is banned (T-1.3). Render text as a child, or use SafeMarkdown.",
        },
        {
          selector: "MemberExpression[property.name='innerHTML']",
          message: "Assigning innerHTML is banned (T-1.3). Use textContent or render with React.",
        },
        {
          selector: "MemberExpression[property.name='outerHTML']",
          message: "Assigning outerHTML is banned (T-1.3).",
        },
      ],

      // A promise that is never awaited in a server component is a request that never happened.
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      // `any` would silently disable the zod boundary this app depends on.
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/consistent-type-imports": "error",
    },
  },
  {
    // Tests may reach for shapes the app never would.
    files: ["**/*.test.ts", "**/*.test.tsx"],
    rules: { "@typescript-eslint/no-unsafe-assignment": "off" },
  },
  // The config files are plain ESM outside the TypeScript project, so the type-aware rules
  // have nothing to say about them. Last, because a later block wins.
  { files: ["**/*.mjs"], ...tseslint.configs.disableTypeChecked },
);
