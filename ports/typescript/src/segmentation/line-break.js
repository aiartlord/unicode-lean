// UAX #14 default line breaking.
//
// A port of the Lean algorithm `Unicode.Segmentation.LineBreak.lineBreaks`,
// whose `lineBreaks_length` theorem fixes the output shape: one
// break-opportunity flag per boundary position. The rule order, rule bodies,
// and snapshot fields below mirror that reference — LB2 through LB31 in
// UAX #14 R7's canonical order, first match winning, the trailing LB31
// breaking every otherwise-unmatched pair.
//
// Where a line may break is a property of a sequence rather than of a code
// point, so the entry point returns a flag per boundary instead of a predicate
// over code points.
//
// Three mechanisms carry the context the rules read:
//
//   * LB1 is applied at lookup time by `resolvedClass`, which folds the
//     tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet.
//     SA needs General_Category to choose between CM and AL.
//   * LB9 — treat X CM* / X ZWJ* as X — is realised through the snapshot, whose
//     fields hold the most recent class that was not CM or ZWJ. LB10, treating
//     a leftover CM or ZWJ as AL, is the fallback taken when no such class
//     exists.
//   * The rules naming a third character — LB15b, LB15c, the LB25 bracket and
//     the fourth LB28a sub-rule — read forward from the position being decided.
//
// Two departures from the Lean. Its positional reads are `lits[i]!` and
// `cps[i]!`, panicking accessors; here an index past the end yields `undefined`
// and every such read is compared against a class, so no access can leave the
// sequence. And its `spSinceNoSp` snapshot field is written by its fold and
// read by no rule, so this module omits it.
//
// The module is dependency-free and reads no files: its four property tables
// are generated into `line-break-tables.js`. That is deliberate — the package
// serves its `src/data/` tables only through the digest-verifying reader
// `security.js` installs, so a segmentation module opening a data file itself
// would be a second data path outside that gate. It also means this module
// runs unchanged on the edge build.

import {
  LINE_BREAK_CLASSES,
  GENERAL_CATEGORY_VALUES,
  EAST_ASIAN_WIDTH_VALUES,
  LINE_BREAK_RANGES,
  GENERAL_CATEGORY_RANGES,
  EAST_ASIAN_WIDTH_RANGES,
  EXTENDED_PICTOGRAPHIC_RANGES,
  PUBLISHED_ROW_COUNT,
} from "./line-break-tables.js";
import { rangeIndex } from "./range-table.js";

export { PUBLISHED_ROW_COUNT };

// ── property lookups ────────────────────────────────────────────────────────

/**
 * The raw Line_Break class of `cp`, before LB1. A codepoint no range covers is
 * `"XX"`, the default LineBreak.txt's own @missing header declares.
 *
 * @param {number} cp
 * @returns {string}
 */
export function rawClass(cp) {
  const index = rangeIndex(LINE_BREAK_RANGES, cp);
  return index < 0 ? "XX" : LINE_BREAK_CLASSES[LINE_BREAK_RANGES.cls[index]];
}

/**
 * The General_Category of `cp`, `"Cn"` when no range covers it — the default
 * UnicodeData.txt declares for an unassigned codepoint.
 *
 * @param {number} cp
 * @returns {string}
 */
export function generalCategory(cp) {
  const index = rangeIndex(GENERAL_CATEGORY_RANGES, cp);
  return index < 0
    ? "Cn"
    : GENERAL_CATEGORY_VALUES[GENERAL_CATEGORY_RANGES.cls[index]];
}

/**
 * The East_Asian_Width of `cp`, `"N"` when the file omits it.
 *
 * @param {number} cp
 * @returns {string}
 */
export function eastAsianWidth(cp) {
  const index = rangeIndex(EAST_ASIAN_WIDTH_RANGES, cp);
  return index < 0
    ? "N"
    : EAST_ASIAN_WIDTH_VALUES[EAST_ASIAN_WIDTH_RANGES.cls[index]];
}

/**
 * Whether `cp` has the Extended_Pictographic property, which LB30b reads.
 *
 * @param {number} cp
 * @returns {boolean}
 */
export function isExtendedPictographic(cp) {
  return rangeIndex(EXTENDED_PICTOGRAPHIC_RANGES, cp) >= 0;
}

// ── LB1, the tailoring applied at lookup ────────────────────────────────────

// The corpus asks for the same few hundred codepoints tens of thousands of
// times, and each miss costs two binary searches.
const resolvedCache = new Map();

function computeResolvedClass(cp) {
  const raw = rawClass(cp);
  switch (raw) {
    case "AI":
    case "SG":
    case "XX":
      return "AL";
    case "CJ":
      return "NS";
    case "SA": {
      // LB1 reads only the two combining-mark categories here; an enclosing
      // mark is not among them.
      const category = generalCategory(cp);
      return category === "Mn" || category === "Mc" ? "CM" : "AL";
    }
    default:
      return raw;
  }
}

/**
 * The Line_Break class `cp` carries once LB1 has tailored it.
 *
 * AI, SG and XX resolve to AL; CJ to NS; SA to CM when the codepoint is a
 * non-spacing or spacing combining mark and to AL otherwise. Every other class
 * is already in the working alphabet.
 *
 * @param {number} cp
 * @returns {string}
 */
export function resolvedClass(cp) {
  const cached = resolvedCache.get(cp);
  if (cached !== undefined) {
    return cached;
  }
  const computed = computeResolvedClass(cp);
  resolvedCache.set(cp, computed);
  return computed;
}

// ── class sets the rules name ───────────────────────────────────────────────

// Classes LB9 absorbs into the character before them.
const CM_ZWJ = new Set(["CM", "ZWJ"]);

// Classes that block LB9's absorption, so a following CM or ZWJ stands on its
// own and LB10 reads it as AL.
const BLOCKS_ABSORB = new Set(["BK", "CR", "LF", "NL", "SP", "ZW"]);

// The left context in which LB15a opens its initial-punctuation window: an
// initial quote standing outside a word.
const PI_WINDOW_OPENERS = new Set([
  "BK", "CR", "LF", "NL", "OP", "QU", "GL", "SP", "ZW",
]);

// Classes that keep an open LB25 numeric chain open.
const NU_CHAIN_EXTENDERS = new Set(["SY", "IS", "CL", "CP", "PR"]);

// Classes that cannot open a line, so an LB15b final quote before one closes
// rather than breaks.
const QUOTE_CLOSERS = new Set([
  "SP", "GL", "WJ", "CL", "QU", "CP", "EX", "IS", "SY", "BK", "CR", "LF",
  "NL", "ZW",
]);

// The start-of-segment set LB20.1 and LB20a require of a hyphen's own left
// context.
const HYPHEN_LEFT_OPENERS = new Set([
  "BK", "CR", "LF", "NL", "SP", "ZW", "CB", "GL",
]);

// East_Asian_Width values LB25 and LB30 exclude.
const EAST_ASIAN_FULL_WIDE = new Set(["F", "W", "H"]);

// The wider set LB19a's tailoring treats as East Asian, Ambiguous included.
const EAST_ASIAN_OR_AMBIGUOUS = new Set(["F", "W", "H", "A"]);

// Classes carrying a mandatory break, which LB6 forbids breaking before.
const MANDATORY = new Set(["BK", "CR", "LF", "NL"]);

// Hangul syllable classes, for LB26 and LB27.
const HANGUL = new Set(["JL", "JV", "JT", "H2", "H3"]);

// U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
const DOTTED_CIRCLE = 0x25cc;

// U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0 moved
// it from class HY to class HH.
const HYPHEN = 0x2010;

function isCmZwj(cls) {
  return CM_ZWJ.has(cls);
}

// Whether the class is QU and the codepoint is initial punctuation, the
// refinement LB15a reads.
function isPiQuote(cp, cls) {
  return cls === "QU" && generalCategory(cp) === "Pi";
}

// Whether the class is QU and the codepoint is final punctuation, the
// refinement LB15b reads.
function isPfQuote(cp, cls) {
  return cls === "QU" && generalCategory(cp) === "Pf";
}

// Whether `cp` is East_Asian_Width F, W or H, the set LB25 and LB30 read.
function isEastAsianFullWide(cp) {
  return EAST_ASIAN_FULL_WIDE.has(eastAsianWidth(cp));
}

// Whether `cp` counts as East Asian for LB19a's tailoring.
function isEastAsianOrAmbiguous(cp) {
  return EAST_ASIAN_OR_AMBIGUOUS.has(eastAsianWidth(cp));
}

// ── the left-hand context a boundary decision reads ─────────────────────────

// The classes and codepoints of the most recent characters LB9 did not absorb,
// plus the running counters the rules keep. Mirrors the Lean `EffSnapshot`:
// an absent neighbour is null.
function initialSnapshot() {
  return {
    // Class of the most recent character that was not CM or ZWJ.
    effPrev: null,
    // Its codepoint — LB20a, LB21a and LB28a name U+2010 and U+25CC.
    effPrevCp: null,
    // Class of the most recent character that was not CM, ZWJ or SP.
    effPrevNoSp: null,
    // Class of the second most recent such character.
    effPrevPrev: null,
    // Its codepoint.
    effPrevPrevCp: null,
    // Whether an LB15a initial-punctuation quote window is open.
    inPiQuoteWindow: false,
    // Length of the current regional-indicator run, for LB30a.
    riRun: 0,
    // Whether an LB25 numeric chain is open.
    inNuChain: false,
  };
}

// The class a CM or ZWJ takes from what it attaches to under LB9, or AL under
// LB10 when nothing absorbs it.
function effectiveClass(cls, effPrev) {
  if (!isCmZwj(cls)) {
    return cls;
  }
  if (effPrev === null) {
    return "AL";
  }
  return BLOCKS_ABSORB.has(effPrev) ? "AL" : cls;
}

// Fold one character into the context. A character LB9 absorbs leaves the
// context untouched, which is what makes the neighbours it records effective
// rather than literal. Mirrors the Lean `buildSnapshots` step.
function advance(s, cp, cls) {
  const effective = effectiveClass(cls, s.effPrev);
  if (isCmZwj(effective)) {
    return s;
  }

  // LB15a opens its window only where an initial-punctuation quote stands
  // outside a word; a space carries an open window forward.
  const leftContextOpens =
    s.effPrev === null || PI_WINDOW_OPENERS.has(s.effPrev);
  let inPiQuoteWindow = false;
  if (isPiQuote(cp, effective) && leftContextOpens) {
    inPiQuoteWindow = true;
  } else if (effective === "SP") {
    inPiQuoteWindow = s.inPiQuoteWindow;
  }

  let inNuChain = false;
  if (effective === "NU") {
    inNuChain = true;
  } else if (s.inNuChain) {
    inNuChain = NU_CHAIN_EXTENDERS.has(effective);
  }

  return {
    effPrev: effective,
    effPrevCp: cp,
    effPrevNoSp: effective === "SP" ? s.effPrevNoSp : effective,
    effPrevPrev: s.effPrev,
    effPrevPrevCp: s.effPrevCp,
    inPiQuoteWindow,
    riRun: effective === "RI" ? s.riRun + 1 : 0,
    inNuChain,
  };
}

// ── lookahead ───────────────────────────────────────────────────────────────

// The class at `index`, or null past the end of the sequence.
function classAt(pairs, index) {
  const entry = pairs[index];
  return entry === undefined ? null : entry.cls;
}

// The codepoint at `index`, or null past the end of the sequence.
function cpAt(pairs, index) {
  const entry = pairs[index];
  return entry === undefined ? null : entry.cp;
}

// LB15b holds when the final quote is last, or when what follows it cannot
// itself open a line.
function finalQuoteCloses(pairs, index) {
  const next = classAt(pairs, index);
  return next === null ? true : QUOTE_CLOSERS.has(next);
}

// The fourth LB28a sub-rule looks past any CM or ZWJ the cluster absorbs, so
// the character it tests is the first significant one ahead.
function nextSignificantIsVf(pairs, index) {
  for (let i = index; i < pairs.length; i += 1) {
    const cls = pairs[i].cls;
    if (!isCmZwj(cls)) {
      return cls === "VF";
    }
  }
  return false;
}

// ── the rule cascade ────────────────────────────────────────────────────────

// Whether a line break opportunity falls immediately before `pairs[index]`,
// given the character before it and the context accumulated from everything
// earlier. `index` is the position being decided, so `index + 1` supplies every
// lookahead the rules take.
function breaksBefore(pairs, index, s) {
  const current = pairs[index];
  if (current === undefined) {
    return true; // LB3
  }
  const previous = pairs[index - 1];
  const prevCp = previous.cp;
  const prevClass = previous.cls;
  const currentCp = current.cp;
  const currentClass = current.cls;
  const ahead = index + 1;

  const eff = effectiveClass(currentClass, s.effPrev);
  const left = isCmZwj(prevClass) ? s.effPrev : prevClass;

  // LB4
  if (prevClass === "BK") return true;
  // LB5
  if (prevClass === "CR" && currentClass === "LF") return false;
  if (prevClass === "CR" || prevClass === "LF" || prevClass === "NL") {
    return true;
  }
  // LB6
  if (MANDATORY.has(currentClass)) return false;
  // LB7
  if (currentClass === "SP" || currentClass === "ZW") return false;
  // LB8
  if (s.effPrevNoSp === "ZW") return true;
  // LB8a
  if (prevClass === "ZWJ") return false;
  // LB9
  if (
    isCmZwj(currentClass) &&
    s.effPrev !== null &&
    !BLOCKS_ABSORB.has(s.effPrev)
  ) {
    return false;
  }
  // LB11
  if (eff === "WJ" || left === "WJ") return false;
  // LB12
  if (left === "GL") return false;
  // LB12a
  if (
    eff === "GL" &&
    !(left === "SP" || left === "BA" || left === "HY" || left === "HH")
  ) {
    return false;
  }
  // LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS that
  // opens a number and follows a space, as in "equals .35".
  if (prevClass === "SP" && eff === "IS" && classAt(pairs, ahead) === "NU") {
    return true;
  }
  // LB13
  if (
    eff === "CL" || eff === "CP" || eff === "EX" || eff === "IS" || eff === "SY"
  ) {
    return false;
  }
  // LB14
  if (s.effPrevNoSp === "OP") return false;
  // LB15a
  if (s.inPiQuoteWindow) return false;
  // LB15b
  if (isPfQuote(currentCp, eff) && finalQuoteCloses(pairs, ahead)) return false;
  // LB15d
  if (eff === "IS") return false;
  // LB16
  if (eff === "NS" && (s.effPrevNoSp === "CL" || s.effPrevNoSp === "CP")) {
    return false;
  }
  // LB17
  if (eff === "B2" && s.effPrevNoSp === "B2") return false;
  // LB18
  if (prevClass === "SP") return true;
  // LB19 and LB19a. A quote neither breaks before nor after, except on the
  // OUTER side of an initial or final punctuation quote standing in contiguous
  // East Asian content — there the default break applies, so a line may break
  // at the quote boundary. The inner side stays unbroken, being the boundary
  // inside the quote's own scope.
  if (eff === "QU") {
    const nextCp = cpAt(pairs, ahead);
    const nextEastAsian = nextCp !== null && isEastAsianOrAmbiguous(nextCp);
    const openQuoteInEastAsian =
      isPiQuote(currentCp, eff) &&
      isEastAsianOrAmbiguous(prevCp) &&
      isEastAsianOrAmbiguous(currentCp) &&
      nextEastAsian;
    if (!openQuoteInEastAsian) return false;
  }
  if (left === "QU") {
    const quoteCp = s.effPrevCp;
    const closeQuoteInEastAsian =
      quoteCp !== null &&
      isPfQuote(quoteCp, "QU") &&
      s.effPrevPrevCp !== null &&
      isEastAsianOrAmbiguous(s.effPrevPrevCp) &&
      isEastAsianOrAmbiguous(quoteCp) &&
      isEastAsianOrAmbiguous(currentCp);
    if (!closeQuoteInEastAsian) return false;
  }
  // LB20
  if (eff === "CB" || left === "CB") return true;

  // LB20.1 and LB20a both require the hyphen's own left context to be outside a
  // word, the same start-of-segment set.
  const hyphenLeftContextOpens =
    s.effPrevPrev === null || HYPHEN_LEFT_OPENERS.has(s.effPrevPrev);
  // LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
  // its own left context is outside a word. A mid-word HH falls through to
  // LB31.
  if (
    left === "HH" &&
    (eff === "AL" || eff === "HL") &&
    hyphenLeftContextOpens
  ) {
    return false;
  }
  // LB20a, with UCD 17.0's right side broadened to HL beside AL.
  if (eff === "AL" || eff === "HL") {
    const hyphenCarriesLeft =
      s.effPrev === "HY" || s.effPrev === "HH" || s.effPrevCp === HYPHEN;
    if (hyphenCarriesLeft && hyphenLeftContextOpens) return false;
  }
  // LB21
  if (eff === "BA" || eff === "HY" || eff === "HH" || eff === "NS") {
    return false;
  }
  if (left === "BB") return false;
  // LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what comes
  // next unless that is itself HL. A BA does not glue here.
  if (
    s.effPrevPrev === "HL" &&
    eff !== "HL" &&
    (s.effPrev === "HY" || s.effPrevCp === HYPHEN)
  ) {
    return false;
  }
  // LB21b
  if (eff === "HL" && left === "SY") return false;
  // LB22
  if (eff === "IN") return false;
  // LB23
  if (eff === "NU" && (left === "AL" || left === "HL")) return false;
  if ((eff === "AL" || eff === "HL") && left === "NU") return false;
  // LB23a
  if ((eff === "ID" || eff === "EB" || eff === "EM") && left === "PR") {
    return false;
  }
  if (eff === "PO" && (left === "ID" || left === "EB" || left === "EM")) {
    return false;
  }
  // LB24
  if ((eff === "AL" || eff === "HL") && (left === "PR" || left === "PO")) {
    return false;
  }
  if ((eff === "PR" || eff === "PO") && (left === "AL" || left === "HL")) {
    return false;
  }
  // LB25, closing an open numeric chain with a CL or CP suffix and a following
  // PO or PR.
  if (
    s.inNuChain &&
    (eff === "CL" || eff === "CP" || eff === "PO" || eff === "PR")
  ) {
    return false;
  }
  // LB25, opening a chain
  if (
    eff === "NU" &&
    (left === "PR" || left === "PO" || left === "HY" || left === "OP" ||
      left === "IS")
  ) {
    return false;
  }
  // LB25, chain body
  if (eff === "NU" && left === "NU") return false;
  // LB25, extending an open chain across a SY
  if (eff === "NU" && left === "SY" && s.inNuChain) return false;
  // LB25, bracketed prefix: a PR joins an OP only when the OP itself opens a
  // number, and neither is East Asian Fullwidth, Wide or Halfwidth.
  if (
    eff === "OP" &&
    left === "PR" &&
    !isEastAsianFullWide(currentCp) &&
    s.effPrevCp !== null &&
    !isEastAsianFullWide(s.effPrevCp) &&
    classAt(pairs, ahead) === "NU"
  ) {
    return false;
  }
  // LB26
  if (
    left === "JL" &&
    (eff === "JL" || eff === "JV" || eff === "H2" || eff === "H3")
  ) {
    return false;
  }
  if ((left === "JV" || left === "H2") && (eff === "JV" || eff === "JT")) {
    return false;
  }
  if ((left === "JT" || left === "H3") && eff === "JT") return false;
  // LB27
  if (HANGUL.has(left) && (eff === "IN" || eff === "PO")) return false;
  if (left === "PR" && HANGUL.has(eff)) return false;
  // LB28
  if ((eff === "AL" || eff === "HL") && (left === "AL" || left === "HL")) {
    return false;
  }

  // LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class AL and
  // stands in for a cluster base throughout.
  const leftIsAksaraBase =
    left === "AK" ||
    left === "AS" ||
    (s.effPrevCp === DOTTED_CIRCLE && s.effPrev === "AL");
  if (
    left === "AP" &&
    (eff === "AK" || eff === "AS" || currentCp === DOTTED_CIRCLE)
  ) {
    return false;
  }
  if (leftIsAksaraBase && (eff === "VF" || eff === "VI")) return false;
  if (
    s.effPrev === "VI" &&
    (s.effPrevPrev === "AK" ||
      s.effPrevPrev === "AS" ||
      s.effPrevPrevCp === DOTTED_CIRCLE) &&
    (eff === "AK" || currentCp === DOTTED_CIRCLE)
  ) {
    return false;
  }
  if (
    leftIsAksaraBase &&
    (eff === "AK" || eff === "AS" || currentCp === DOTTED_CIRCLE) &&
    nextSignificantIsVf(pairs, ahead)
  ) {
    return false;
  }
  // LB29
  if ((eff === "AL" || eff === "HL") && left === "IS") return false;
  // LB30, where the bracket must not be East Asian Fullwidth, Wide or
  // Halfwidth.
  if (
    eff === "OP" &&
    (left === "AL" || left === "HL" || left === "NU") &&
    !isEastAsianFullWide(currentCp)
  ) {
    return false;
  }
  if (
    (eff === "AL" || eff === "HL" || eff === "NU") &&
    left === "CP" &&
    !isEastAsianFullWide(prevCp)
  ) {
    return false;
  }
  // LB30a
  if (eff === "RI" && s.riRun % 2 === 1) return false;
  // LB30b
  if (eff === "EM" && left === "EB") return false;
  if (
    eff === "EM" &&
    s.effPrevCp !== null &&
    isExtendedPictographic(s.effPrevCp) &&
    generalCategory(s.effPrevCp) === "Cn"
  ) {
    return false;
  }
  // LB31
  return true;
}

// ── entry points ────────────────────────────────────────────────────────────

/**
 * One break-opportunity flag per boundary of the codepoint sequence, so a
 * sequence of n codepoints yields n + 1 flags — the shape the Lean
 * `lineBreaks_length` theorem fixes.
 *
 * Entry 0 is false — LB2 forbids a break at the start of text — and entry n is
 * true per LB3, which requires one at the end.
 *
 * @param {ReadonlyArray<number>} cps
 * @returns {boolean[]}
 */
export function lineBreaks(cps) {
  const pairs = new Array(cps.length);
  for (let i = 0; i < cps.length; i += 1) {
    pairs[i] = { cp: cps[i], cls: resolvedClass(cps[i]) };
  }
  const out = new Array(cps.length + 1);
  let s = initialSnapshot();
  for (let i = 0; i < pairs.length; i += 1) {
    out[i] = i === 0 ? false : breaksBefore(pairs, i, s);
    s = advance(s, pairs[i].cp, pairs[i].cls);
  }
  out[cps.length] = true; // LB3
  return out;
}

/**
 * The codepoint sequence split at every break opportunity — the runs a renderer
 * may place on separate lines.
 *
 * @param {ReadonlyArray<number>} cps
 * @returns {number[][]}
 */
export function lineRuns(cps) {
  const breaks = lineBreaks(cps);
  const out = [];
  let current = [];
  for (let i = 0; i < cps.length; i += 1) {
    current.push(cps[i]);
    if (breaks[i + 1]) {
      out.push(current);
      current = [];
    }
  }
  if (current.length > 0) {
    out.push(current);
  }
  return out;
}
