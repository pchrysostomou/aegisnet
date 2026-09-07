import { describe, expect, it } from "vitest";

import { QUEUE, isWorthRemembering, safeNext } from "./safe-path";

describe("safeNext", () => {
  it("keeps a case the analyst was already looking at", () => {
    expect(safeNext("/incidents/5A4419F6-AF88-4B2B-BDAB-672F20331AF7")).toBe(
      "/incidents/5a4419f6-af88-4b2b-bdab-672f20331af7",
    );
  });

  it("keeps a section this app serves", () => {
    expect(safeNext("/incidents")).toBe("/incidents");
    expect(safeNext("/assets")).toBe("/assets");
    expect(safeNext("/audit")).toBe("/audit");
  });

  it("sends everything it does not recognise to the queue", () => {
    expect(safeNext("")).toBe(QUEUE);
    expect(safeNext("/assets/1")).toBe(QUEUE);
    expect(safeNext("/settings")).toBe(QUEUE);
  });

  it("cannot be talked into leaving this app", () => {
    for (const hostile of [
      "//evil.test",
      "///evil.test",
      "/\\evil.test",
      "https://evil.test",
      "http://evil.test/incidents",
      "/incidents/../../evil",
      "javascript:alert(1)",
      "/incidents/5a4419f6-af88-4b2b-bdab-672f20331af7@evil.test",
      "/incidents/5a4419f6-af88-4b2b-bdab-672f20331af7/../../evil",
      "\n/incidents",
      "/incidents\r\nSet-Cookie: x=1",
    ]) {
      expect(safeNext(hostile), hostile).toBe(QUEUE);
    }
  });

  it("returns a string it built, never the one it was given", () => {
    const raw = "/incidents/5a4419f6-af88-4b2b-bdab-672f20331af7";
    const result = safeNext(raw);
    expect(result).toBe(raw);
    // The line below used to claim "same characters, different object", which is not a thing a
    // JavaScript string can be: `toBe` is `Object.is`, and two equal primitives are the same
    // value. What is worth asserting is that a path is returned *whole* — a sanitiser that
    // silently truncated would still satisfy the equality above for the empty string.
    expect(result).toHaveLength(raw.length);
  });
});

describe("isWorthRemembering", () => {
  it("remembers only somewhere it would send you back to", () => {
    expect(isWorthRemembering("/incidents")).toBe(true);
    expect(isWorthRemembering("/assets")).toBe(true);
    expect(isWorthRemembering("/incidents/5a4419f6-af88-4b2b-bdab-672f20331af7")).toBe(true);
    expect(isWorthRemembering("/")).toBe(false);
    expect(isWorthRemembering("/login")).toBe(false);
    expect(isWorthRemembering("//evil.test")).toBe(false);
  });
});
