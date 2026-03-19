import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3011,
    proxy: {
      "/api": "http://localhost:8011",
      "/admin": "http://localhost:8011",
    },
  },
});
