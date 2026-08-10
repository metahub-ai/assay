/**
 * Terminal rendering.
 *
 * Most of this is about what happens when the terminal is NOT a
 * terminal. Colour codes in a log file, a spinner in CI output, and a
 * bar chart with no number beside it are all ways of making output
 * worse for the people least able to work around it.
 */
import { describe, expect, it, vi } from "vitest";
import {
  colorEnabled,
  createTheme,
  padEndVisible,
  scoreBar,
  statusGlyph,
  spinnerEnabled,
  unicodeEnabled,
  visibleLength,
  wrapText,
  Spinner,
  boxChars,
  truncateVisible,
} from "../src/term";
import { renderReport } from "../src/render";
import type { AssayReport } from "../src/types";

describe("colorEnabled", () => {
  // https://no-color.org — an informal standard, but widely honoured,
  // and the people who set it have a reason.
  it("obeys NO_COLOR above everything else", () => {
    expect(colorEnabled({ NO_COLOR: "1", FORCE_COLOR: "1" }, true)).toBe(false);
  });

  it("ignores an EMPTY NO_COLOR, per the spec", () => {
    expect(colorEnabled({ NO_COLOR: "" }, true)).toBe(true);
  });

  it("honours FORCE_COLOR when stdout is a pipe", () => {
    expect(colorEnabled({ FORCE_COLOR: "1" }, false)).toBe(true);
  });

  it("treats FORCE_COLOR=0 as no override", () => {
    expect(colorEnabled({ FORCE_COLOR: "0" }, false)).toBe(false);
  });

  it("stays plain for a dumb terminal", () => {
    expect(colorEnabled({ TERM: "dumb" }, true)).toBe(false);
  });

  it("defaults to off when stdout is not a TTY", () => {
    expect(colorEnabled({}, false)).toBe(false);
  });
});

describe("unicodeEnabled", () => {
  it("can be turned off explicitly", () => {
    expect(unicodeEnabled({ ASSAY_ASCII: "1" })).toBe(false);
  });
});

/**
 * Cursor-redrawing output is hard for speech synthesizers and braille
 * displays to follow, and motion can cause discomfort. One environment
 * variable is a very cheap fix for both.
 */
describe("spinnerEnabled", () => {
  it("animates on a real terminal", () => {
    expect(spinnerEnabled({}, true)).toBe(true);
  });

  it("can be disabled explicitly for screen readers and motion sensitivity", () => {
    expect(spinnerEnabled({ ASSAY_NO_SPINNER: "1" }, true)).toBe(false);
  });

  // Runners set CI variously as `1`, `true`, and `True`.
  it.each(["1", "true", "True"])("stays silent in CI (CI=%s)", (value) => {
    expect(spinnerEnabled({ CI: value }, true)).toBe(false);
  });

  it("stays silent when stderr is a pipe", () => {
    // isTTY is `undefined` rather than `false` when piped.
    expect(spinnerEnabled({}, undefined)).toBe(false);
  });
});

describe("theme", () => {
  it("emits no escape sequences when colour is off", () => {
    const t = createTheme({ color: false });
    for (const paint of [t.pass, t.fail, t.warn, t.muted, t.bold, t.heading, t.accent, t.code]) {
      expect(paint("x")).toBe("x");
    }
  });

  it("emits escape sequences when colour is on", () => {
    expect(createTheme({ color: true }).pass("x")).toMatch(/\[/);
  });

  it("falls back to words when unicode is unavailable", () => {
    const t = createTheme({ color: false, unicode: false });
    expect(t.glyph("pass")).toBe("PASS");
    expect(t.glyph("fail")).toBe("FAIL");
  });

  // A 300-column terminal produces lines nobody can read across. The
  // floor is 40 rather than 60: a 45-column terminal was being handed
  // 60-column rules that it then hard-wrapped, which is worse than a
  // narrow layout.
  it("clamps the width to a readable range", () => {
    expect(createTheme({ width: 500 }).width).toBe(100);
    expect(createTheme({ width: 10 }).width).toBe(40);
  });

  // The only way to control layout in a pipe, where
  // `process.stdout.columns` is undefined.
  it("honours COLUMNS", () => {
    const prev = process.env["COLUMNS"];
    process.env["COLUMNS"] = "55";
    try {
      expect(createTheme().width).toBe(55);
    } finally {
      if (prev === undefined) delete process.env["COLUMNS"];
      else process.env["COLUMNS"] = prev;
    }
  });
});

describe("scoreBar", () => {
  const t = createTheme({ color: false, unicode: true });

  it("fills in proportion to the value", () => {
    expect(scoreBar(t, 100, true, 10)).toBe("██████████");
    expect(scoreBar(t, 0, true, 10)).toBe("░░░░░░░░░░");
    expect(scoreBar(t, 50, true, 10)).toBe("█████░░░░░");
  });

  // The whole point of the scorer: an unmeasured axis must not render
  // like a measured zero — and must not look like a section RULE
  // either, which it did when both were drawn with `─`.
  it("renders an unmeasured axis distinctly from a measured zero", () => {
    expect(scoreBar(t, 0, false, 6)).toBe("······");
    expect(scoreBar(t, 0, false, 6)).not.toBe(scoreBar(t, 0, true, 6));
  });

  it("does not draw an unmeasured axis with the rule character", () => {
    expect(scoreBar(t, 0, false, 6)).not.toContain("─");
  });

  // A zero used to render entirely muted, because the coloured span was
  // empty — so the worst value on the page carried the least ink.
  it("colours the trough at a failing score", () => {
    const coloured = createTheme({ color: true, unicode: true });
    expect(scoreBar(coloured, 0, true, 6)).toMatch(/38;5;167/);
  });

  it("clamps out-of-range values instead of overflowing the row", () => {
    expect(visibleLength(scoreBar(t, 150, true, 10))).toBe(10);
    expect(visibleLength(scoreBar(t, -20, true, 10))).toBe(10);
  });
});

describe("layout helpers", () => {
  it("measures length ignoring ANSI, so padding stays aligned", () => {
    const coloured = createTheme({ color: true }).pass("hello");
    expect(coloured.length).toBeGreaterThan(5);
    expect(visibleLength(coloured)).toBe(5);
  });

  it("pads to a visible width, not a byte width", () => {
    const coloured = createTheme({ color: true }).pass("ab");
    expect(visibleLength(padEndVisible(coloured, 10))).toBe(10);
  });

  it("does not truncate something already too long", () => {
    expect(padEndVisible("abcdef", 3)).toBe("abcdef");
  });

  it("wraps to the given width", () => {
    for (const line of wrapText("word ".repeat(40), 30).split("\n")) {
      expect(line.length).toBeLessThanOrEqual(30);
    }
  });
});

/** Collect everything a spinner writes, without it reaching the reporter. */
function captureStderr(): { written: string[]; restore: () => void } {
  const written: string[] = [];
  const orig = process.stderr.write.bind(process.stderr);

  (process.stderr as any).write = (s: string) => (written.push(s), true);
  return {
    written,
    restore: () => {
      (process.stderr as any).write = orig;
    },
  };
}

describe("Spinner", () => {
  it("writes exactly one line when disabled, so CI logs stay readable", () => {
    const { written, restore } = captureStderr();
    try {
      new Spinner(createTheme({ color: false }), false).start("working").stop();
    } finally {
      restore();
    }
    expect(written).toEqual(["  working\n"]);
  });

  it("is safe to stop without starting, and to stop twice", () => {
    const s = new Spinner(createTheme({ color: false }), false);
    expect(() => {
      s.stop();
      s.stop();
    }).not.toThrow();
  });

  it("logs each update on its own line when disabled", () => {
    const { written, restore } = captureStderr();
    try {
      const s = new Spinner(createTheme({ color: false }), false).start("one");
      s.update("two");
      s.stop();
    } finally {
      restore();
    }
    expect(written).toEqual(["  one\n", "  two\n"]);
  });

  describe("when animating", () => {
    it("redraws in place and clears the line on stop", () => {
      vi.useFakeTimers();
      const { written, restore } = captureStderr();
      try {
        const s = new Spinner(createTheme({ color: false }), true).start("working");
        vi.advanceTimersByTime(300);
        s.stop();
      } finally {
        restore();
        vi.useRealTimers();
      }
      // Carriage returns, not newlines — a spinner that scrolls the
      // terminal is worse than no spinner at all.
      expect(written.length).toBeGreaterThan(1);
      expect(written.every((s) => s.startsWith("\r"))).toBe(true);
      expect(written.join("")).not.toContain("\n");
    });

    it('shows elapsed seconds, because the honest answer to "is it stuck?" is a rising number', () => {
      vi.useFakeTimers();
      const { written, restore } = captureStderr();
      try {
        const s = new Spinner(createTheme({ color: false }), true).start("working");
        vi.advanceTimersByTime(5_000);
        s.stop();
      } finally {
        restore();
        vi.useRealTimers();
      }
      expect(written.join("")).toMatch(/\d+s/);
    });

    it("prints a final line when given one", () => {
      const { written, restore } = captureStderr();
      try {
        new Spinner(createTheme({ color: false }), true).start("x").stop("done");
      } finally {
        restore();
      }
      expect(written.at(-1)).toBe("done\n");
    });
  });
});

describe("boxChars", () => {
  it("uses box drawing when unicode is available", () => {
    expect(boxChars(createTheme({ unicode: true })).tl).toBe("╭");
  });

  it("falls back to ASCII otherwise", () => {
    const b = boxChars(createTheme({ unicode: false }));
    expect(b.tl).toBe("+");
    expect(b.h).toBe("-");
  });
});

// ── The report renderer ──────────────────────────────────────────────

function report(over: Partial<AssayReport> = {}): AssayReport {
  return {
    schemaVersion: "1",
    subject: {
      kind: "skill",
      name: "demo",
      source: { type: "directory", path: "." },
      digest: { sha256: "a".repeat(64) },
    },
    suite: { id: "s", version: "1", checksDigest: "b".repeat(64) },
    environment: { runner: "test", scanContext: { credentials: "anonymous", network: "none" } },
    results: [
      {
        checkId: "c-fail",
        checkVersion: "1.0.0",
        title: "Declares its tools",
        category: "safety",
        determinism: "deterministic",
        weight: 1,
        axis: "safety",
        blocking: true,
        status: "fail",
        summary: "no allowed-tools declared",
        remediation: "Declare the minimum set the skill needs.",
        evidence: [{ type: "file", path: "SKILL.md", line: 3 }],
      },
      {
        checkId: "c-pass",
        checkVersion: "1.0.0",
        title: "Has a licence",
        category: "care",
        determinism: "deterministic",
        weight: 1,
        axis: "care",
        status: "pass",
        summary: "LICENSE found",
      },
    ],
    score: {
      overall: 62,
      formula: "weighted",
      axes: {
        integrity: { value: 90, coverage: 1, checkIds: [] },
        safety: { value: 0, coverage: 1, checkIds: ["c-fail"] },
        care: { value: 100, coverage: 0.5, checkIds: ["c-pass"] },
        behavior: { value: 0, coverage: 0, checkIds: [] },
      },
    },
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    ...over,
  } as AssayReport;
}

describe("renderReport", () => {
  const theme = createTheme({ color: false, unicode: true, width: 80 });
  const opts = { quiet: false, theme };

  it("leads with the subject and the headline score", () => {
    const out = renderReport(report(), opts);
    const overall = out.indexOf("OVERALL");
    const finding = out.indexOf("NEEDS FIXING");
    expect(overall).toBeGreaterThan(-1);
    // The number people scroll for must not be below the check list —
    // this is the ordering bug the previous renderer had.
    expect(overall).toBeLessThan(finding);
  });

  it("puts failures above warnings and passes", () => {
    const out = renderReport(report(), opts);
    expect(out.indexOf("NEEDS FIXING")).toBeLessThan(out.indexOf("Has a licence"));
  });

  it("shows the 95% confidence interval on the behavior axis when the run bounded it", () => {
    const withCi = report({
      results: [
        {
          checkId: "behaves-as-documented",
          checkVersion: "1.1.0",
          title: "Behaves as documented",
          category: "behavioral",
          determinism: "replayable",
          weight: 5,
          axis: "behavior",
          status: "pass",
          summary: "behaves",
          evidence: [{ type: "metric", name: "score_95ci_halfwidth", value: 6.2, unit: "points" }],
        },
      ],
      score: {
        overall: 93,
        formula: "weighted",
        axes: {
          integrity: { value: 100, coverage: 1, checkIds: [] },
          safety: { value: 100, coverage: 1, checkIds: [] },
          care: { value: 100, coverage: 1, checkIds: [] },
          behavior: { value: 93, coverage: 1, checkIds: ["behaves-as-documented"] },
        },
      },
    });
    const line = renderReport(withCi, opts)
      .split("\n")
      .find((l) => /behavior/.test(l))!;
    expect(line).toMatch(/± ?6/);
  });

  it("omits the interval when a single sample makes it meaningless (half-width 100)", () => {
    const noCi = report({
      results: [
        {
          checkId: "behaves-as-documented",
          checkVersion: "1.1.0",
          title: "Behaves as documented",
          category: "behavioral",
          determinism: "replayable",
          weight: 5,
          axis: "behavior",
          status: "pass",
          summary: "behaves",
          evidence: [{ type: "metric", name: "score_95ci_halfwidth", value: 100, unit: "points" }],
        },
      ],
      score: {
        overall: 93,
        formula: "weighted",
        axes: {
          integrity: { value: 100, coverage: 1, checkIds: [] },
          safety: { value: 100, coverage: 1, checkIds: [] },
          care: { value: 100, coverage: 1, checkIds: [] },
          behavior: { value: 93, coverage: 1, checkIds: ["behaves-as-documented"] },
        },
      },
    });
    const line = renderReport(noCi, opts)
      .split("\n")
      .find((l) => /behavior/.test(l))!;
    expect(line).not.toMatch(/±/);
  });

  it("marks a blocking failure as blocking", () => {
    expect(renderReport(report(), opts)).toMatch(/blocking/);
  });

  it("prints evidence as path:line so an editor can jump to it", () => {
    expect(renderReport(report(), opts)).toContain("SKILL.md:3");
  });

  it("prints the remediation", () => {
    expect(renderReport(report(), opts)).toMatch(/Declare the minimum set/);
  });

  // Units are free-form strings from checks, so concatenation produced
  // "1of 3" and "5.30-10" on a real behavioral run.
  it("separates a metric from its unit", () => {
    const r = report();
    r.results[0]!.evidence = [
      { type: "metric", name: "resisted", value: 1, unit: "of 3" },
      { type: "metric", name: "score", value: 5.3, unit: "0-10" },
      { type: "metric", name: "coverage", value: 80, unit: "%" },
    ];
    const out = renderReport(r, opts);
    expect(out).toContain("resisted: 1 of 3");
    expect(out).toContain("score: 5.3 0-10");
    expect(out).toContain("coverage: 80%");
  });

  it("prints coverage beside every axis", () => {
    const out = renderReport(report(), opts);
    expect(out).toMatch(/safety.*100% measured/);
    expect(out).toMatch(/care.*50% measured/);
  });

  // An axis nothing measured must read as "we could not tell", never as
  // a zero the artifact earned.
  it("renders an unmeasured axis as not measured, with no number", () => {
    const out = renderReport(report(), opts);
    const line = out.split("\n").find((l) => l.includes("behavior"))!;
    expect(line).toContain("not measured");
    expect(line).not.toMatch(/\b0\b/);
  });

  it("refuses to print a headline when there was too little signal", () => {
    const r = report();
    delete (r.score as { overall?: number }).overall;
    const out = renderReport(r, opts);
    expect(out).toMatch(/not enough was measured/);
  });

  it("hides passes in quiet mode but keeps failures", () => {
    const out = renderReport(report(), { ...opts, quiet: true });
    expect(out).toContain("Declares its tools");
    expect(out).not.toContain("Has a licence");
  });

  it("tallies statuses in the footer", () => {
    expect(renderReport(report(), opts)).toMatch(/1 failure.*1 pass/);
  });

  // Appending an "s" produced "14 passs · 2 skippeds · 3 n/as".
  it("pluralises the tally correctly", () => {
    const r = report();
    const base = r.results[1]!;
    r.results = [
      ...r.results,
      { ...base, checkId: "p2" },
      { ...base, checkId: "s1", status: "skip" },
      { ...base, checkId: "s2", status: "skip" },
      { ...base, checkId: "n1", status: "neutral" },
    ];
    const out = renderReport(r, opts);
    expect(out).toContain("2 passed");
    expect(out).toContain("2 skipped");
    expect(out).toContain("1 n/a");
    expect(out).not.toMatch(/passs|skippeds|n\/as/);
  });

  it("names where a remote artifact came from", () => {
    const out = renderReport(report(), {
      ...opts,
      provenance: { kind: "git", spec: "owner/repo", resolved: "abc1234" },
    });
    expect(out).toContain("abc1234");
  });

  it("says so when a registry integrity hash was checked", () => {
    const out = renderReport(report(), {
      ...opts,
      provenance: { kind: "npm", spec: "npm:x", integrity: "sha512-abc" },
    });
    expect(out).toMatch(/integrity verified \(sha512\)/);
  });

  it("emits no escape sequences under NO_COLOR", () => {
    expect(renderReport(report(), opts)).not.toMatch(/\[/);
  });

  it("keeps every line within the terminal width", () => {
    const wide = renderReport(report(), { quiet: false, theme });
    for (const line of wide.split("\n")) {
      expect(visibleLength(line)).toBeLessThanOrEqual(theme.width + 4);
    }
  });
});

describe("statusGlyph", () => {
  const t = createTheme({ color: false, unicode: true });
  it.each([
    ["pass", "✔"],
    ["fail", "✘"],
    ["warn", "▲"],
    ["skip", "·"],
    ["neutral", "–"],
  ] as const)("renders %s", (kind, glyph) => {
    expect(statusGlyph(t, kind)).toBe(glyph);
  });
});

/**
 * `blocking` is a property of the check DEFINITION, so a warning from a
 * blocking check was labelled "(blocking)" as well. That reads as "this
 * is stopping your build" when it is not — and is exactly backwards for
 * a finding that was downgraded precisely because it does not block.
 */
describe("the blocking label", () => {
  const theme = createTheme({ color: false, unicode: true, width: 80 });
  const withStatus = (status: "fail" | "warn"): AssayReport => {
    const r = report();
    r.results[0] = { ...r.results[0]!, status, blocking: true };
    return r;
  };

  it("appears on a blocking failure", () => {
    expect(renderReport(withStatus("fail"), { quiet: false, theme })).toContain("(blocking)");
  });

  it("does NOT appear on a warning from a blocking check", () => {
    expect(renderReport(withStatus("warn"), { quiet: false, theme })).not.toContain("(blocking)");
  });
});

/**
 * Width maths in terminal CELLS, not code units.
 *
 * `.length` is wrong twice over: an emoji is two units and one glyph, a
 * CJK ideograph is one unit and two cells. Every padded column was
 * computed from it, so a Japanese summary ragged the whole table — and
 * `.slice()` cut surrogate pairs in half, printing a replacement
 * character into, among other places, the evidence excerpt for a
 * malicious install script.
 */
describe("cell-accurate width", () => {
  it.each([
    ["ascii", "hello", 5],
    ["CJK", "日本語", 6],
    ["emoji", "🎉", 2],
    ["mixed", "a日b", 4],
  ])("measures %s", (_n, s, want) => {
    expect(visibleLength(s)).toBe(want);
  });

  it("ignores ANSI when measuring", () => {
    expect(visibleLength(createTheme({ color: true }).fail("hello"))).toBe(5);
  });

  it("pads CJK to the right cell width", () => {
    expect(visibleLength(padEndVisible("日本語", 10))).toBe(10);
  });

  it("never leaves a broken surrogate behind", () => {
    const t = truncateVisible(`${"e".repeat(50)}🎉🎉🎉`, 54);
    expect(t).not.toContain("�");
    expect([...t].every((c) => c.codePointAt(0)! !== 0xfffd)).toBe(true);
  });

  it("truncates CJK to a cell budget, not a code-unit budget", () => {
    expect(visibleLength(truncateVisible("日本語のとても長い名前", 10))).toBeLessThanOrEqual(10);
  });

  it("returns the input untouched when it already fits", () => {
    expect(truncateVisible("short", 20)).toBe("short");
  });
});

/**
 * A token longer than the whole budget used to be emitted whole, so a
 * 66-character CJK name blew a 138-cell line into an 80-column report.
 */
describe("wrapText hard-breaks over-long tokens", () => {
  it.each([
    ["a long URL", `See https://example.com/${"a".repeat(200)}`],
    ["a long CJK name", `Name "${"日本語のとても長い名前".repeat(6)}" is invalid.`],
    ["a long path", `at ${"/very-long-directory-name".repeat(12)}/file.ts`],
  ])("keeps every line within the budget for %s", (_n, text) => {
    for (const line of wrapText(text, 72).split("\n")) {
      expect(visibleLength(line)).toBeLessThanOrEqual(72);
    }
  });

  it("still wraps ordinary prose on word boundaries", () => {
    const out = wrapText("the quick brown fox jumps over the lazy dog", 20);
    expect(out.split("\n").every((l) => !l.startsWith(" "))).toBe(true);
  });
});

/**
 * `ASSAY_ASCII=1` used to be half-honoured: only the status glyphs and
 * box characters consulted it, so the ellipsis, em dash, arrow and
 * middot survived a flag whose entire purpose is that none do.
 */
describe("ASCII mode leaves no non-ASCII behind", () => {
  const ascii = createTheme({ unicode: false, color: false });

  it.each([
    ["ellipsis", () => ascii.ellipsis],
    ["arrow", () => ascii.arrow],
    ["dot", () => ascii.dot],
    ["dash", () => ascii.dash],
  ])("%s is ASCII", (_n, get) => {
    expect(/^[\x20-\x7e]+$/.test(get())).toBe(true);
  });

  it("uses equal-width status glyphs so the column does not ragged", () => {
    const widths = new Set(
      (["pass", "fail", "warn", "neutral", "skip", "error"] as const).map(
        (k) => ascii.glyph(k).length,
      ),
    );
    expect(widths.size).toBe(1);
  });

  it("renders a whole report with no non-ASCII characters", () => {
    const out = renderReport(report(), { quiet: false, theme: ascii });
    const offenders = [...out].filter((c) => c.codePointAt(0)! > 0x7e);
    expect(offenders).toEqual([]);
  });
});
