/-
  Unicode.Width

  UAX #11 East Asian Width — per-codepoint and per-string display
  width calculation. Implements the standard "wcwidth-style" rules:

    * Width 0 — control characters (general category Cc), combining
                marks (general category Mn or Me), zero-width joiner
                U+200D, zero-width non-joiner U+200C, default-ignorable
                codepoints with general category Cf.
    * Width 2 — codepoints with East_Asian_Width = F (Fullwidth) or
                W (Wide).
    * Width 1 — all other codepoints, including N (Neutral),
                Na (Narrow), H (Halfwidth), and (under
                `AmbiguousMode.narrow`) A (Ambiguous).

  Codepoints with East_Asian_Width = A take their width from the
  `AmbiguousMode` parameter: `narrow` (the Western default,
  matching POSIX `wcwidth`) maps A to 1; `wide` (the CJK default)
  maps A to 2.

  Two string-level widths are provided:

    * `displayWidth` — sum of per-codepoint widths.  Over-counts
      emoji ZWJ sequences (a family `👨‍👩‍👧` sums to 6 even though
      it renders as a single width-2 glyph) and is the right
      primitive for plain-text or pre-tokenised input.
    * `displayWidthClusters` — UTS #51 / UAX #29 cluster-aware.
      Chunks codepoints into grapheme clusters, classifies each
      as emoji or text, and assigns width 2 to every emoji
      cluster regardless of its constituent codepoint count.
      Matches `wcswidth`-style terminal column behaviour.

  Variation selectors U+FE0E (text presentation) and U+FE0F (emoji
  presentation) are width 0 — they modify the *previous* codepoint's
  presentation rather than occupying display columns themselves.
-/

import Unicode.Generated.EastAsianWidth
import Unicode.Generated.DerivedGeneralCategory
import Unicode.Generated.EmojiData
import Unicode.Segmentation.GraphemeBreak

namespace Unicode.Width

open Unicode.Generated.EastAsianWidth (EastAsianWidthClass)
open Unicode.Generated.DerivedGeneralCategory (GC)

/-- How to classify codepoints with East_Asian_Width = A (Ambiguous).
    `narrow` matches POSIX `wcwidth` and Western terminals;
    `wide` matches CJK terminals and `wcwidth-cjk`. -/
inductive AmbiguousMode where
  | narrow
  | wide
  deriving DecidableEq, Repr, Inhabited

/-- True iff `cp` has General_Category = Mn (Mark, Non-Spacing) or
    Me (Mark, Enclosing). Combining marks attach to the preceding
    base character and so contribute zero display width. Mc
    (Mark, Spacing Combining) does occupy a column and is *not*
    included here. -/
def isCombiningMark (cp : Nat) : Bool :=
  match Unicode.Generated.DerivedGeneralCategory.lookup cp with
  | .Mn | .Me => true
  | .Lu | .Ll | .Lt | .Lm | .Lo
  | .Mc
  | .Nd | .Nl | .No
  | .Pc | .Pd | .Ps | .Pe | .Pi | .Pf | .Po
  | .Sm | .Sc | .Sk | .So
  | .Zs | .Zl | .Zp
  | .Cc | .Cf | .Cs | .Co | .Cn => false

/-- True iff `cp` has General_Category = Cc (Control). Includes
    the C0 controls (U+0000..U+001F), DEL (U+007F), and the C1
    controls (U+0080..U+009F). -/
def isControl (cp : Nat) : Bool :=
  match Unicode.Generated.DerivedGeneralCategory.lookup cp with
  | .Cc => true
  | .Lu | .Ll | .Lt | .Lm | .Lo
  | .Mn | .Mc | .Me
  | .Nd | .Nl | .No
  | .Pc | .Pd | .Ps | .Pe | .Pi | .Pf | .Po
  | .Sm | .Sc | .Sk | .So
  | .Zs | .Zl | .Zp
  | .Cf | .Cs | .Co | .Cn => false

/-- True iff `cp` is U+200C ZERO WIDTH NON-JOINER, U+200D ZERO
    WIDTH JOINER, or one of the U+FE00..U+FE0F variation selectors.
    Each contributes zero display width — joiners and selectors
    modify adjacent characters. -/
def isZeroWidthFormatter (cp : Nat) : Bool :=
  cp == 0x200C || cp == 0x200D
    || (Nat.ble 0xFE00 cp && Nat.ble cp 0xFE0F)

/-- The display width of a single codepoint under `mode`. -/
def codepointWidth (mode : AmbiguousMode) (cp : Nat) : Nat :=
  if isControl cp then 0
  else if isCombiningMark cp then 0
  else if isZeroWidthFormatter cp then 0
  else
    match Unicode.Generated.EastAsianWidth.lookup cp with
    | .F | .W => 2
    | .H | .Na | .N => 1
    | .A =>
      match mode with
      | .narrow => 1
      | .wide   => 2

/-- The total display width of a codepoint sequence under `mode`,
    obtained by summing per-codepoint widths. ZWJ / variation
    selectors / combining marks contribute 0.  Sums per-codepoint
    widths without grapheme-cluster awareness: an emoji ZWJ
    sequence `base + ZWJ + ... + ZWJ + base` sums to twice the
    base count rather than the rendered width 2.  Use
    `displayWidthClusters` for the UTS #51-aware variant that
    collapses ZWJ chains to a single cluster.  For non-emoji text
    and for individual emoji codepoints the two agree. -/
def displayWidth (mode : AmbiguousMode) (cps : List Nat) : Nat :=
  cps.foldl (fun acc cp => acc + codepointWidth mode cp) 0

-- ═══════════════════════════════════════════════════════════════════════════════
-- GRAPHEME-CLUSTER-AWARE DISPLAY WIDTH
--
-- The per-codepoint `displayWidth` over-counts emoji ZWJ sequences:
-- a family `👨‍👩‍👧` (5 codepoints — three emoji bases at width 2 each,
-- two ZWJs at width 0) sums to 6, but renders as a single width-2
-- glyph in any compliant renderer. The grapheme-cluster-aware
-- variant chunks codepoints via UAX #29 grapheme breaks, then takes
-- the max per-codepoint width within each cluster (combining marks
-- and ZWJs contribute 0, the emoji base contributes 2, so cluster
-- max is 2 — the rendered width). This matches terminal-column
-- behaviour and `wcswidth`-style libraries.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a regional indicator symbol letter
    (U+1F1E6..U+1F1FF). Two consecutive regional indicators form
    a flag sequence which is rendered as a single width-2 glyph. -/
def isRegionalIndicator (cp : Nat) : Bool :=
  Nat.ble 0x1F1E6 cp && Nat.ble cp 0x1F1FF

/-- True iff a single grapheme cluster renders as an emoji glyph
    rather than as plain text. The render-as-emoji conditions per
    UTS #51 / EastAsianWidth common practice:

      * any codepoint has Emoji_Presentation,
      * the cluster contains U+FE0F (emoji variation selector),
      * the cluster contains a regional indicator (flag),
      * any codepoint has Extended_Pictographic (catches the
        ZWJ-joined family / profession / hair sequences whose
        bases all have Extended_Pictographic).

    Emoji clusters are rendered at width 2 regardless of their
    constituent codepoints' East_Asian_Width values. -/
def isEmojiCluster (cluster : List Nat) : Bool :=
  cluster.any (fun cp =>
    Unicode.Generated.EmojiData.isEmojiPresentation cp
      || cp = 0xFE0F
      || isRegionalIndicator cp
      || Unicode.Generated.EmojiData.isExtendedPictographic cp)

/-- Display width of a single grapheme cluster. Emoji clusters
    render at width 2 (per UTS #51 / common terminal behaviour);
    text clusters take the max per-codepoint width within the
    cluster (combining marks contribute 0, so a base + combining
    cluster has the base's width). -/
def clusterWidth (mode : AmbiguousMode) (cluster : List Nat) : Nat :=
  if isEmojiCluster cluster then 2
  else
    cluster.foldl (fun acc cp =>
      let w := codepointWidth mode cp
      if Nat.ble acc w then w else acc) 0

/-- Slice `cps` into grapheme clusters using UAX #29 break positions. -/
def graphemeClusters (cps : List Nat) : List (List Nat) :=
  let breaks := Unicode.Segmentation.GraphemeBreak.graphemeBreaks cps
  let step := fun (acc : List (List Nat) × List Nat) (p : Nat × Bool) =>
    let (clusters, current) := acc
    let (cp, brk) := p
    let (clusters', current') :=
      if brk ∧ ! current.isEmpty then (clusters ++ [current], ([] : List Nat))
      else (clusters, current)
    (clusters', current' ++ [cp])
  let (clusters, current) := (cps.zip breaks).foldl step (([], []) : List (List Nat) × List Nat)
  if ! current.isEmpty then clusters ++ [current] else clusters

/-- The display width of `cps` computed cluster-wise: chunk via
    UAX #29 grapheme breaks, take the max codepoint-width within
    each cluster, sum across clusters. This is the correct width
    for emoji ZWJ sequences (a family is one width-2 cluster
    rather than the codepoint-summed width 6) and for combining-
    mark clusters (`a + ̈` is one width-1 cluster, not 1 + 0). -/
def displayWidthClusters (mode : AmbiguousMode) (cps : List Nat) : Nat :=
  (graphemeClusters cps).foldl
    (fun acc cluster => acc + clusterWidth mode cluster) 0

end Unicode.Width
