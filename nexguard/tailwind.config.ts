import type { Config } from "tailwindcss";

export default {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        soc: {
          lightBg: "#F8FAFC",
          lightCard: "#FFFFFF",
          lightBorder: "#E2E8F0",
          lightBorderHover: "#CBD5E1",
          lightText: "#0F172A",
          lightMuted: "#64748B",
          dark: "rgb(var(--soc-dark) / <alpha-value>)",
          card: "rgb(var(--soc-card) / <alpha-value>)",
          cardHover: "rgb(var(--soc-card-hover) / <alpha-value>)",
          border: "rgb(var(--soc-border) / <alpha-value>)",
          borderLight: "rgb(var(--soc-border-light) / <alpha-value>)",
          accent: "rgb(var(--soc-accent) / <alpha-value>)",
          accentGlow: "rgb(var(--soc-accent-glow) / <alpha-value>)",
          blue: "rgb(var(--soc-blue) / <alpha-value>)",
          blueDark: "rgb(var(--soc-blue-dark) / <alpha-value>)",
          emerald: "rgb(var(--soc-emerald) / <alpha-value>)",
          amber: "rgb(var(--soc-amber) / <alpha-value>)",
          rose: "rgb(var(--soc-rose) / <alpha-value>)",
          text: "rgb(var(--soc-text) / <alpha-value>)",
          muted: "rgb(var(--soc-muted) / <alpha-value>)",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          '"Segoe UI"',
          "Roboto",
          '"Helvetica Neue"',
          "Arial",
          "sans-serif",
        ],
        mono: [
          '"JetBrains Mono"',
          '"Fira Code"',
          "Consolas",
          '"Courier New"',
          "monospace",
        ],
      },
    },
  },
  plugins: [],
} satisfies Config;
