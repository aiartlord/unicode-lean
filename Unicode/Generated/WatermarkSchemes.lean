/-
  Unicode.Generated.WatermarkSchemes

  Inventory of published AI-text-watermark schemes that the
  `AiWatermarkDetectability` detector probes for.  Source data
  lives in `Unicode/Ucd/Curated/WatermarkSchemes.txt` and is
  pinned in `Unicode/Ucd/Curated/SHA256SUMS`.

  Each entry has a stable opaque tag, a cue-class tag drawn from
  a fixed inductive vocabulary, and an informal citation.
  `AiWatermarkDetectability.subThreatCueClass` maps each
  implementation-level sub-threat to the cue class it probes
  for, exposing the conceptual link between the published scheme
  and the codepoint-level heuristic that surfaces it.
-/

namespace Unicode.Generated.WatermarkSchemes

/-- The fixed inductive vocabulary of watermark cue classes.
    `AiWatermarkDetectability` maps each of its sub-threats onto
    a member of this enum so callers can report which conceptual
    scheme a codepoint-level heuristic implicates. -/
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
