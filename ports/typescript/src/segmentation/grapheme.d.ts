// UAX #29 default extended grapheme cluster segmentation.
//
// A port of the Lean algorithm
// `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`. `graphemeBreaks` returns
// one cluster-boundary flag per boundary position, so a sequence of n
// codepoints yields n + 1 flags, entry 0 the GB1 start-of-text break and entry
// n the GB2 end-of-text break, both always true.
//
// The module is dependency-free and reads no files: its property tables are
// generated into source, so it runs unchanged on the edge build.

/** A UAX #29 Grapheme_Cluster_Break property value. */
export type GraphemeClusterBreakValue =
  | "Other" | "CR" | "LF" | "Control" | "Extend" | "ZWJ"
  | "Regional_Indicator" | "Prepend" | "SpacingMark"
  | "L" | "V" | "T" | "LV" | "LVT";

/** A UAX #29 Indic_Conjunct_Break value, the sub-property GB9c reads. */
export type IndicConjunctBreakValue =
  | "None" | "Consonant" | "Extend" | "Linker";

/**
 * The Grapheme_Cluster_Break class of `cp`, `"Other"` when no range covers it —
 * the default GraphemeBreakProperty.txt's own @missing header declares.
 */
export function graphemeClusterBreak(cp: number): GraphemeClusterBreakValue;

/**
 * The Indic_Conjunct_Break class of `cp`, `"None"` when no range covers it —
 * the default DerivedCoreProperties.txt's own @missing header declares.
 */
export function indicConjunctBreak(cp: number): IndicConjunctBreakValue;

/** Whether `cp` has the Extended_Pictographic property, which GB11 reads. */
export function isExtendedPictographic(cp: number): boolean;

/**
 * One cluster-boundary flag per boundary of the codepoint sequence: n
 * codepoints yield n + 1 flags, with the GB1 start-of-text and GB2 end-of-text
 * breaks at the ends.
 */
export function graphemeBreaks(cps: ReadonlyArray<number>): boolean[];

/**
 * The codepoints between consecutive boundaries — the clusters a renderer
 * treats as single user-perceived characters.
 */
export function graphemeClusters(cps: ReadonlyArray<number>): number[][];

/**
 * How many data rows the pinned corpus carries, counted from the canonical
 * GraphemeBreakTest.txt at generation.
 */
export const GRAPHEME_PUBLISHED_ROW_COUNT: number;
