/-
  Unicode.Generated.WatermarkSchemes

  Inventory of published AI-text-watermark schemes that the
  deferred Layer-6 K3 detector would need to recognise.  Source
  data lives in `Unicode/Ucd/Curated/WatermarkSchemes.txt` and is
  pinned in `Unicode/Ucd/Curated/SHA256SUMS`.

  Each entry has a stable opaque tag, a cue-class tag drawn from
  a fixed inductive vocabulary, and an informal citation.  The
  cue-class tag is what a future K3 detector would dispatch on;
  the citation is for human auditing.

  Pre-staging table — no current detector consumes it; reserved
  for the deferred Layer-6 K3 family.
-/

namespace Unicode.Generated.WatermarkSchemes

/-- The fixed inductive vocabulary of watermark cue classes.  A
    future K3 detector dispatches on this enum. -/
inductive CueClass where
  /-- Token-distribution biased toward a pseudorandom green-list
      per context (Kirchenbauer-Geipel-Wen 2023 style). -/
  | greenListBias
  /-- Output token sequence follows a pseudorandom function of
      the prefix; cryptographically private (Aaronson 2022,
      Christ-Gunn-Zamir 2023). -/
  | pseudorandomSeq
  /-- Paragraph-level distributional skew under a chosen
      embedding. -/
  | semanticDrift
  deriving DecidableEq, Repr, Inhabited

/-- A single watermark-scheme entry. -/
structure Entry where
  tag      : String
  cue      : CueClass
  citation : String
  deriving Repr, Inhabited

/-- Raw text embedded at compile time. -/
def rawText : String := include_str "../Ucd/Curated/WatermarkSchemes.txt"

/-- Parse the cue-class token. -/
@[inline]
private def parseCue? : String → Option CueClass
  | "green_list_bias"  => some .greenListBias
  | "pseudorandom_seq" => some .pseudorandomSeq
  | "semantic_drift"   => some .semanticDrift
  | other              => Function.const String none other

/-- Trim ASCII whitespace, returning a plain `String`. -/
@[inline]
private def trimS (s : String) : String := (String.trimAscii s).toString

/-- Parse one row.  Format: `<tag>; <cue>; <citation>`. -/
@[inline]
private def parseLine (line : String) : Option Entry :=
  let t := trimS line
  if t.isEmpty then none
  else if t.startsWith "#" then none
  else
    match (t.splitOn ";").map trimS with
    | tag :: cueStr :: rest =>
      match parseCue? cueStr with
      | some cue => some { tag := tag, cue := cue,
                           citation := ";".intercalate rest }
      | none     => none
    | tooFew => Function.const (List String) none tooFew

/-- Catalog of published watermark schemes. -/
def entries : Array Entry :=
  ((rawText.splitOn "\n").filterMap parseLine).toArray

theorem entries_count : entries.size = 3 := by native_decide

theorem kgw_present : entries.any (fun e => e.tag = "KGW") = true := by
  native_decide

end Unicode.Generated.WatermarkSchemes
