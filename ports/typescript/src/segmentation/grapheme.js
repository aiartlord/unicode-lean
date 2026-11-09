// UAX #29 default extended grapheme cluster segmentation.
//
// A port of the Lean algorithm
// `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`, whose
// `graphemeBreaks_eq_spec` theorem relates it to the declarative UAX #29
// GB1-GB999 specification. The state fields, rule order and transitions below
// mirror that reference: the first matching rule wins, and the trailing GB999
// breaks every otherwise-unmatched pair.
//
// Where a cluster boundary falls is a property of a sequence rather than of a
// code point, so the entry point returns one flag per boundary position: a
// sequence of n codepoints yields n + 1 flags, entry 0 the GB1 start-of-text
// break and entry n the GB2 end-of-text break, both always true.
//
// Three pieces of left context carry what the rules read, each a field of the
// scan state: the previous codepoint's class, the GB11 emoji-pictograph
// window, and the GB9c Indic-conjunct window, plus the regional-indicator run
// length GB12 and GB13 count parity over. Where the Lean carries an optional
// previous class, this module carries null, the convention the line breaker
// already uses for an absent neighbour.
//
// Two of the three properties the rules read are generated into
// `grapheme-tables.js`. The third, Extended_Pictographic, is the table LB30b
// reads, so GB11 imports `isExtendedPictographic` from the line breaker rather
// than carrying a second copy. The module is dependency-free and reads no
// files, so it runs unchanged on the edge build.

import {
  GRAPHEME_CLUSTER_BREAK_VALUES,
  INDIC_CONJUNCT_BREAK_VALUES,
  GRAPHEME_CLUSTER_BREAK_RANGES,
  INDIC_CONJUNCT_BREAK_RANGES,
  GRAPHEME_PUBLISHED_ROW_COUNT,
} from "./grapheme-tables.js";
import { rangeIndex } from "./range-table.js";
import { isExtendedPictographic } from "./line-break.js";

export { GRAPHEME_PUBLISHED_ROW_COUNT, isExtendedPictographic };

// ── property lookups ────────────────────────────────────────────────────────

/**
 * The Grapheme_Cluster_Break class of `cp`, `"Other"` when no range covers it —
 * the default GraphemeBreakProperty.txt's own @missing header declares.
 *
 * @param {number} cp
 * @returns {string}
 */
export function graphemeClusterBreak(cp) {
  const index = rangeIndex(GRAPHEME_CLUSTER_BREAK_RANGES, cp);
  return index < 0
    ? "Other"
    : GRAPHEME_CLUSTER_BREAK_VALUES[GRAPHEME_CLUSTER_BREAK_RANGES.cls[index]];
}

/**
 * The Indic_Conjunct_Break class of `cp`, `"None"` when no range covers it —
 * the default DerivedCoreProperties.txt's own @missing header declares.
 *
 * @param {number} cp
 * @returns {string}
 */
export function indicConjunctBreak(cp) {
  const index = rangeIndex(INDIC_CONJUNCT_BREAK_RANGES, cp);
  return index < 0
    ? "None"
    : INDIC_CONJUNCT_BREAK_VALUES[INDIC_CONJUNCT_BREAK_RANGES.cls[index]];
}

// ── class sets the rules name ───────────────────────────────────────────────

// Classes GB4 breaks after and GB5 breaks before.
const CONTROL_LIKE = new Set(["Control", "CR", "LF"]);

// The vowel and syllable classes GB6 admits after a leading jamo.
const AFTER_L = new Set(["L", "V", "LV", "LVT"]);

// ── the left-hand context a boundary decision reads ─────────────────────────

// The GB11 window: whether the scan has just passed an Extended_Pictographic,
// and whether a ZWJ has followed it.
const EPIC_NONE = "none";
const EPIC_AFTER_EP = "afterEP";
const EPIC_AFTER_EP_ZWJ = "afterEPZWJ";

// The GB9c window: whether the scan has passed an Indic_Conjunct_Break
// consonant, and whether a linker has followed it.
const INCB_NONE = "none";
const INCB_CONSONANT = "consonant";
const INCB_LINKER = "linker";

// The running scan state, mirroring the Lean `State`: an absent previous class
// is null, which is the condition GB1 tests.
function initialState() {
  return {
    prevClass: null,
    epicState: EPIC_NONE,
    inCbState: INCB_NONE,
    riRun: 0,
  };
}

// Whether a cluster boundary falls immediately before `cp`, given the running
// state. UAX #29 GB1 through GB999 in canonical order.
function breaksBefore(cp, s) {
  if (s.prevClass === null) {
    return true; // GB1: start of text
  }
  const bc = graphemeClusterBreak(cp);
  const inCb = indicConjunctBreak(cp);
  const isEp = isExtendedPictographic(cp);
  const pc = s.prevClass;

  // GB3
  if (pc === "CR" && bc === "LF") return false;
  // GB4
  if (CONTROL_LIKE.has(pc)) return true;
  // GB5
  if (CONTROL_LIKE.has(bc)) return true;
  // GB6
  if (pc === "L" && AFTER_L.has(bc)) return false;
  // GB7
  if ((pc === "LV" || pc === "V") && (bc === "V" || bc === "T")) return false;
  // GB8
  if ((pc === "LVT" || pc === "T") && bc === "T") return false;
  // GB9
  if (bc === "Extend" || bc === "ZWJ") return false;
  // GB9a
  if (bc === "SpacingMark") return false;
  // GB9b
  if (pc === "Prepend") return false;
  // GB9c: Consonant (Extend | Linker)* Linker (Extend | Linker)* x Consonant
  if (s.inCbState === INCB_LINKER && inCb === "Consonant") return false;
  // GB11: ExtPict Extend* ZWJ x ExtPict
  if (s.epicState === EPIC_AFTER_EP_ZWJ && isEp) return false;
  // GB12 / GB13: an odd-parity regional-indicator run extends
  if (bc === "Regional_Indicator" && s.riRun % 2 === 1) return false;
  // GB999
  return true;
}

// The state after consuming `cp`. Mirrors the Lean `advance`, which computes
// the update independently of the break decision so the caller records the
// break and moves on.
function advance(cp, s) {
  const bc = graphemeClusterBreak(cp);
  const inCb = indicConjunctBreak(cp);
  const isEp = isExtendedPictographic(cp);

  let epicState = EPIC_NONE;
  if (isEp) {
    epicState = EPIC_AFTER_EP;
  } else if (s.epicState === EPIC_AFTER_EP && bc === "Extend") {
    epicState = EPIC_AFTER_EP;
  } else if (s.epicState === EPIC_AFTER_EP && bc === "ZWJ") {
    epicState = EPIC_AFTER_EP_ZWJ;
  }

  let inCbState = INCB_NONE;
  if (inCb === "Consonant") {
    inCbState = INCB_CONSONANT;
  } else if (s.inCbState === INCB_CONSONANT && inCb === "Linker") {
    inCbState = INCB_LINKER;
  } else if (s.inCbState === INCB_CONSONANT && inCb === "Extend") {
    inCbState = INCB_CONSONANT;
  } else if (s.inCbState === INCB_LINKER && inCb === "Linker") {
    inCbState = INCB_LINKER;
  } else if (s.inCbState === INCB_LINKER && inCb === "Extend") {
    inCbState = INCB_LINKER;
  }

  return {
    prevClass: bc,
    epicState,
    inCbState,
    riRun: bc === "Regional_Indicator" ? s.riRun + 1 : 0,
  };
}

// ── entry points ────────────────────────────────────────────────────────────

/**
 * One cluster-boundary flag per boundary of the codepoint sequence, so a
 * sequence of n codepoints yields n + 1 flags.
 *
 * Entry 0 is the GB1 start-of-text break and entry n the GB2 end-of-text
 * break, both always true.
 *
 * @param {ReadonlyArray<number>} cps
 * @returns {boolean[]}
 */
export function graphemeBreaks(cps) {
  const out = new Array(cps.length + 1);
  let s = initialState();
  for (let i = 0; i < cps.length; i += 1) {
    out[i] = breaksBefore(cps[i], s);
    s = advance(cps[i], s);
  }
  out[cps.length] = true; // GB2
  return out;
}

/**
 * The codepoints between consecutive boundaries — the clusters a renderer
 * treats as single user-perceived characters.
 *
 * @param {ReadonlyArray<number>} cps
 * @returns {number[][]}
 */
export function graphemeClusters(cps) {
  const breaks = graphemeBreaks(cps);
  const out = [];
  let current = [];
  for (let i = 0; i < cps.length; i += 1) {
    if (breaks[i] && current.length > 0) {
      out.push(current);
      current = [];
    }
    current.push(cps[i]);
  }
  if (current.length > 0) {
    out.push(current);
  }
  return out;
}
