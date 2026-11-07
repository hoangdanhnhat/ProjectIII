import { useCallback, useEffect, useState } from "react";

export type Theme = "light" | "dark";

const THEME_KEY = "dfir.theme";

function currentTheme(): Theme {
  return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
}

/**
 * useTheme reflects the theme already applied by public/theme.js (stored
 * choice, else the OS preference) and persists manual toggles.
 */
export function useTheme() {
  const [theme, setTheme] = useState<Theme>(currentTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme((previous) => {
      const next: Theme = previous === "dark" ? "light" : "dark";
      // Suppress the color transitions for one frame so the swap does not
      // smear, then let them return for ordinary hover and state changes.
      const root = document.documentElement;
      root.classList.add("theme-switching");
      root.setAttribute("data-theme", next);
      void root.offsetWidth;
      requestAnimationFrame(() => root.classList.remove("theme-switching"));
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch {
        // Storage can be unavailable; the theme still applies to this tab.
      }
      return next;
    });
  }, []);

  return { theme, toggle };
}
