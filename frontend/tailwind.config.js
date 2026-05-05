/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Backgrounds: deep black layers
        bg: "#0a0a0a",
        surface: "#121212",
        "surface-2": "#1a1a1a",
        "surface-3": "#212121",
        border: "#262626",
        "border-strong": "#333333",

        // Text
        fg: "#ffffff",
        "fg-muted": "#9ca3af",
        "fg-faint": "#6b7280",

        // Single accent: red (ReliaQuest-style)
        accent: "#dc2626",
        "accent-soft": "#991b1b",
        "accent-hover": "#ef4444",

        // Severity scale — restrained, only red is loud
        info: "#94a3b8",
        success: "#65a30d",
        warning: "#ca8a04",
        danger: "#dc2626",
        critical: "#991b1b",
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
        sans: [
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "sans-serif",
        ],
      },
      animation: {
        "pulse-soft": "pulse-soft 2.5s ease-in-out infinite",
      },
      keyframes: {
        "pulse-soft": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.55" },
        },
      },
    },
  },
  plugins: [],
};
