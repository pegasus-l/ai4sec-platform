import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}", "./src/**/*.{ts,tsx}", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "var(--text)",
        panel: "var(--panel)",
        line: "var(--line)",
        muted: "var(--muted)",
        signal: "var(--danger)",
        ocean: "var(--accent)",
        leaf: "var(--accent-2)"
      }
    }
  },
  plugins: []
};

export default config;
