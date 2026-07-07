/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          navy: '#020212',      // Deep Space Navy from your logo background
          slate: '#131926',     // Dark Slate Grey for cards and sidebars
          blue: '#25a5ff',      // Electric Sky Blue from your logo typography
          muted: '#94a3b8',     // Sleek Muted Grey for description text
          crimson: '#ef4444',   // Red alert flags for caught malware signatures
        }
      }
    },
  },
  plugins: [],
}