/** @type {import('tailwindcss').Config} */
    module.exports = {
      content: {
        relative: true,
        files: ["*.html", "src/*", "./src/**/*.rs"],
      },
      theme: {
        extend: {},
      },
      plugins: [require("daisyui")],
    }
    