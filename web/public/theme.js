(function () {
  var stored = null;
  try {
    stored = localStorage.getItem("dfir.theme");
  } catch {
    stored = null; // storage can be unavailable in hardened browser modes
  }
  var prefersDark =
    window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  var theme = stored === "light" || stored === "dark" ? stored : prefersDark ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", theme);
})();
