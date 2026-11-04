import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Vitest under jsdom exposes import.meta.url as an http URL, so resolve
// relative to the project root (the working directory of `npm test`).
const read = (name: string) => readFileSync(resolve(process.cwd(), "src/styles", name), "utf8");

const tokensCSS = read("tokens.css");

function block(selector: string): string {
  const start = tokensCSS.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`missing token block: ${selector}`);
  return tokensCSS.slice(start, tokensCSS.indexOf("}", start));
}

function tokens(selector: string): Record<string, string> {
  const out: Record<string, string> = {};
  const pattern = /(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{3,8})\s*;/g;
  const body = block(selector);
  for (let match = pattern.exec(body); match; match = pattern.exec(body)) {
    out[match[1].replace(/^--/, "")] = match[2];
  }
  return out;
}

function channel(value: number): number {
  const normalized = value / 255;
  return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  let body = hex.slice(1);
  if (body.length === 3) {
    body = body
      .split("")
      .map((char) => char + char)
      .join("");
  }
  const r = Number.parseInt(body.slice(0, 2), 16);
  const g = Number.parseInt(body.slice(2, 4), 16);
  const b = Number.parseInt(body.slice(4, 6), 16);
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(foreground: string, background: string): number {
  const samples = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (samples[0] + 0.05) / (samples[1] + 0.05);
}

const LIGHT = tokens(":root");
const DARK = tokens('html[data-theme="dark"]');

// Every pair that can render text must meet WCAG AA (4.5:1) in both themes.
const TEXT_PAIRS: Array<[string, string]> = [
  ["text", "surface"],
  ["text", "bg"],
  ["text-soft", "surface"],
  ["text-soft", "surface-2"],
  ["muted", "surface"],
  ["muted", "bg"],
  ["link", "surface"],
  ["danger", "danger-bg"],
  ["warn", "warn-bg"],
  ["ok", "ok-bg"],
  ["btn-primary-text", "btn-primary-bg"],
];

describe("theme tokens", () => {
  it("defines the same tokens in light and dark", () => {
    expect(Object.keys(DARK).sort()).toEqual(Object.keys(LIGHT).sort());
  });

  for (const [theme, set] of [
    ["light", LIGHT],
    ["dark", DARK],
  ] as const) {
    it(`meets WCAG AA contrast in ${theme}`, () => {
      for (const [fg, bg] of TEXT_PAIRS) {
        expect(set[fg], `${theme}: missing --${fg}`).toBeDefined();
        expect(set[bg], `${theme}: missing --${bg}`).toBeDefined();
        const ratio = contrast(set[fg], set[bg]);
        expect(ratio, `${theme}: ${fg} on ${bg} = ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5);
      }
    });
  }

  it("keeps literal colors out of component styles", () => {
    for (const name of ["base.css", "components.css"]) {
      expect(read(name), `${name} must only use var(--token)`).not.toMatch(/#[0-9a-fA-F]{3,8}/);
    }
  });
});
