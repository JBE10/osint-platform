/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"] ,
  theme: {
    extend: {
      colors: {
        ink: "#0b1220",
        slate: "#101827",
        sand: "#f4efe6",
        ember: "#ff7a3d",
        mist: "#b5c2d9"
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        mono: ["'IBM Plex Mono'", "monospace"],
        body: ["'Space Grotesk'", "sans-serif"]
      },
      boxShadow: {
        glow: "0 0 30px rgba(255, 122, 61, 0.25)",
      },
      keyframes: {
        fadeUp: {
          "0%": { opacity: 0, transform: "translateY(12px)" },
          "100%": { opacity: 1, transform: "translateY(0)" }
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" }
        }
      },
      animation: {
        fadeUp: "fadeUp 0.6s ease-out",
        shimmer: "shimmer 1.8s linear infinite"
      }
    },
  },
  plugins: [],
};
