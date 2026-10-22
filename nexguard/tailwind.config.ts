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
          dark: "#0B0F19",
          card: "#111827",
          cardHover: "#1F2937",
          border: "#1E293B",
          borderLight: "#334155",
          accent: "#0284C7",
          accentGlow: "#0EA5E9",
          blue: "#2563EB",
          blueDark: "#1D4ED8",
          emerald: "#059669",
          amber: "#D97706",
          rose: "#DC2626",
          text: "#F1F5F9",
          muted: "#94A3B8",
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
