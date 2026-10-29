(function () {
  "use strict";
  var key = "dfir.theme";
  var theme = null;
  try {
    theme = localStorage.getItem(key);
  } catch (err) {
    theme = null;
  }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.dataset.theme = theme;
})();
