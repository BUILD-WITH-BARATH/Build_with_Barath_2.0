import { defineConfig } from "vitest/config";

export default defineConfig({
  // This package has no CSS at all, but Vite's config loader otherwise walks up
  // to the monorepo root and picks up bola-frontend's postcss.config.js (which
  // depends on tailwindcss/autoprefixer, not installed here). An inline empty
  // config short-circuits that file search.
  css: { postcss: { plugins: [] } },
  test: {
    environment: "node",
  },
});
