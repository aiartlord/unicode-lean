// UAX #14 default line breaking.
//
// A port of the Lean algorithm `Unicode.Segmentation.LineBreak.lineBreaks`.
// `lineBreaks` returns one break-opportunity flag per boundary position, so a
// sequence of n codepoints yields n + 1 flags — the shape the Lean
// `lineBreaks_length` theorem fixes. Entry 0 is false, since LB2 forbids a
// break at the start of text, and entry n is true per LB3.
//
// The module is dependency-free and reads no files: its property tables are
// generated into source, so it runs unchanged on the edge build.

/** A UAX #14 Line_Break property value, LB1-tailored or raw. */
export type LineBreakClass =
  | "AI" | "AK" | "AL" | "AP" | "AS" | "B2" | "BA" | "BB" | "BK" | "CB"
  | "CJ" | "CL" | "CM" | "CP" | "CR" | "EB" | "EM" | "EX" | "GL" | "H2"
  | "H3" | "HH" | "HL" | "HY" | "ID" | "IN" | "IS" | "JL" | "JT" | "JV"
  | "LF" | "NL" | "NS" | "NU" | "OP" | "PO" | "PR" | "QU" | "RI" | "SA"
  | "SG" | "SP" | "SY" | "VF" | "VI" | "WJ" | "XX" | "ZW" | "ZWJ";

/** A UAX #44 section 5.7.1 General_Category value. */
export type GeneralCategoryValue =
  | "Lu" | "Ll" | "Lt" | "Lm" | "Lo"
  | "Mn" | "Mc" | "Me"
  | "Nd" | "Nl" | "No"
  | "Pc" | "Pd" | "Ps" | "Pe" | "Pi" | "Pf" | "Po"
  | "Sm" | "Sc" | "Sk" | "So"
  | "Zs" | "Zl" | "Zp"
  | "Cc" | "Cf" | "Cs" | "Co" | "Cn";

/** A UAX #11 East_Asian_Width value. */
export type EastAsianWidthValue = "A" | "F" | "H" | "N" | "Na" | "W";

/**
 * The raw Line_Break class of `cp`, before LB1. A codepoint no range covers is
 * `"XX"`, the default LineBreak.txt's own @missing header declares.
 */
export function rawClass(cp: number): LineBreakClass;

/**
 * The Line_Break class `cp` carries once LB1 has tailored it: AI, SG and XX
 * resolve to AL; CJ to NS; SA to CM for a non-spacing or spacing combining mark
 * and to AL otherwise.
 */
export function resolvedClass(cp: number): LineBreakClass;

/**
 * The General_Category of `cp`, `"Cn"` when no range covers it — the default
 * UnicodeData.txt declares for an unassigned codepoint.
 */
export function generalCategory(cp: number): GeneralCategoryValue;

/** The East_Asian_Width of `cp`, `"N"` when the file omits it. */
export function eastAsianWidth(cp: number): EastAsianWidthValue;

/** Whether `cp` has the Extended_Pictographic property, which LB30b reads. */
export function isExtendedPictographic(cp: number): boolean;

/**
 * One break-opportunity flag per boundary of the codepoint sequence: n
 * codepoints yield n + 1 flags, entry 0 false per LB2 and entry n true per LB3.
 */
export function lineBreaks(cps: ReadonlyArray<number>): boolean[];

/**
 * The codepoint sequence split at every break opportunity — the runs a renderer
 * may place on separate lines.
 */
export function lineRuns(cps: ReadonlyArray<number>): number[][];

/**
 * How many data rows the pinned corpus carries, counted from the canonical
 * LineBreakTest.txt at generation.
 */
export const PUBLISHED_ROW_COUNT: number;
