import { describe, expect, it } from "vitest";

import { QUEUE, isWorthRemembering, safeNext } from "./safe-path";

describe("safeNext", () => {
  it("keeps a case the analyst was already looking at", () => {
    expect(safeNext("/incidents/5A4419F6-AF88-4B2B-BDAB-672F20331AF7")).toBe(
      "/incidents/5a4419f6-af88-4b2b-bdab-672f20331af7",
    );
  });

  it("sends everything it does not recognise to the queue", () => {
    expect(safeNext("/incidents")).toBe(QUEUE);
    expect(safeNext("")).toBe(QUEUE);
    expect(safeNext("/assets")).toBe(QUEUE);
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
    // Same characters, different object: nothing is passed through by reference.
    expect(result).not.toBe(`${raw}`.padEnd(raw.length + 1));
  });
});

describe("isWorthRemembering", () => {
  it("remembers a case, and does not bother with the root", () => {
    expect(isWorthRemembering("/incidents/abc")).toBe(true);
    expect(isWorthRemembering("/")).toBe(false);
    expect(isWorthRemembering("/login")).toBe(false);
  });
});
