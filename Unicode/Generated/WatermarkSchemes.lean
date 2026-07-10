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

import Unicode.Generated.WatermarkSchemesData

namespace Unicode.Generated.WatermarkSchemes

set_option maxRecDepth 100000

/-- Raw text embedded at compile time. -/
def rawText : String := include_str "../Ucd/Curated/WatermarkSchemes.txt"

/-- Parse the cue-class token. -/
@[inline]
def parseCue? : String → Option CueClass
  | "green_list_bias"  => some .greenListBias
  | "pseudorandom_seq" => some .pseudorandomSeq
  | "semantic_drift"   => some .semanticDrift
  | other              => Function.const String none other

/-- Trim ASCII whitespace, returning a plain `String`. -/
@[inline]
def trimS (s : String) : String := (String.trimAscii s).toString

/-- Parse one row.  Format: `<tag>; <cue>; <citation>`. -/
@[inline]
def parseLine (line : String) : Option Entry :=
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
def entriesParsed : Array Entry :=
  ((rawText.splitOn "\n").filterMap parseLine).toArray

/-- The materialized catalog, consumed downstream. -/
def entries : List Entry := entriesList

theorem entries_count : entries.length = 3 := by decide +kernel

-- Build-time drift gate.
#eval do
  unless entriesList.toArray == entriesParsed do
    throw (IO.userError "WatermarkSchemes drift: list ≠ parsed")

theorem kgw_present : entries.any (fun e => e.tag = "KGW") = true := by
  decide +kernel

end Unicode.Generated.WatermarkSchemes
