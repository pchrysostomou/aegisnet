import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

/**
 * WCAG AA contrast, computed from the stylesheet rather than asserted in a document.
 *
 * A severity badge is the one place this dashboard uses colour to carry meaning, so it is the
 * one place a contrast failure would cost a reader information. (Colour is never the *only*
 * carrier — every badge prints its number and its word — but a label nobody can read is not a
 * label.) The palette is parsed out of `globals.css` so the numbers cannot drift from it.
 */
const css = readFileSync(path.join(process.cwd(), "src", "app", "globals.css"), "utf8");

function palette(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [, name, value] of block.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6});/g)) {
    out[name] = value;
  }
  return out;
}

/** The first `:root` block is the light theme; the one inside the media query is dark. */
const light = palette(css.slice(css.indexOf(":root {"), css.indexOf("@media")));
const dark = palette(css.slice(css.indexOf("@media")));

function channel(component: number): number {
  const c = component / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  const value = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(value.slice(i, i + 2), 16));
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

export function contrast(a: string, b: string): number {
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (high + 0.05) / (low + 0.05);
}

const AA_NORMAL = 4.5;
const AA_LARGE = 3.0;

describe("the light theme meets WCAG AA", () => {
  const surface = light.surface;
  it.each(["sev-1", "sev-2", "sev-3", "sev-4", "sev-5"])(
    "%s on the surface it is drawn on",
    (name) => {
      expect(contrast(light[name], surface)).toBeGreaterThanOrEqual(AA_LARGE);
    },
  );

  it("body text is comfortably above the normal-text threshold", () => {
    expect(contrast(light.text, light.bg)).toBeGreaterThanOrEqual(AA_NORMAL);
    expect(contrast(light.text, light.surface)).toBeGreaterThanOrEqual(AA_NORMAL);
  });

  it("muted text still clears AA, because it carries timestamps and detail", () => {
    expect(contrast(light["muted-text"], light.surface)).toBeGreaterThanOrEqual(AA_NORMAL);
  });

  it("links and the focus ring clear AA against their background", () => {
    expect(contrast(light.accent, light.surface)).toBeGreaterThanOrEqual(AA_NORMAL);
  });
});

describe("the dark theme meets WCAG AA", () => {
  it.each(["sev-1", "sev-2", "sev-3", "sev-4", "sev-5"])("%s on the surface", (name) => {
    expect(contrast(dark[name], dark.surface)).toBeGreaterThanOrEqual(AA_LARGE);
  });

  it("body, muted text and links clear AA", () => {
    expect(contrast(dark.text, dark.bg)).toBeGreaterThanOrEqual(AA_NORMAL);
    expect(contrast(dark["muted-text"], dark.surface)).toBeGreaterThanOrEqual(AA_NORMAL);
    expect(contrast(dark.accent, dark.surface)).toBeGreaterThanOrEqual(AA_NORMAL);
  });
});
