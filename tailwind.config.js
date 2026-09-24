/**
 * Tailwind build config for CVSS Guru (npm run build:css → app/static/css/app.css).
 *
 * The zinc/neutral/amber/red/green scales are mapped onto CSS custom properties
 * defined in app/templates/partials/theme_head.html, so utility classes follow the
 * light/dark theme and the per-section accent color at runtime.
 */
const tok = (name) => `rgb(var(--${name}) / <alpha-value>)`;
const scale = (prefix, shades) =>
  Object.fromEntries(shades.map((s) => [s, tok(`${prefix}-${s}`)]));

const zinc = scale("zinc", [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950]);

module.exports = {
  // Class names are also written in Python-generated HTML snippets (e.g. app/routers/auth.py)
  content: ["./app/templates/**/*.html", "./app/**/*.py"],
  theme: {
    extend: {
      colors: {
        zinc,
        neutral: zinc,
        amber: scale("amber", [300, 400, 500, 600, 700, 800]),
        red: { 300: tok("red-300"), 400: tok("red-400") },
        green: { 400: tok("green-400") },
      },
    },
  },
  plugins: [],
};
