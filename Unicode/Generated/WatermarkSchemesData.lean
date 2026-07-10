/-
  Unicode.Generated.WatermarkSchemesData

  Materialized AI-watermark scheme catalog (curated), pinned as a `List`
  literal so membership tests reduce in the kernel. The parser and
  `include_str` source live in `Unicode.Generated.WatermarkSchemes`,
  which imports this module and carries the build-time drift gate. The
  `CueClass`/`Entry` types are defined here to avoid a circular import.
-/

namespace Unicode.Generated.WatermarkSchemes

set_option maxRecDepth 1000000

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

/-- One watermark-scheme catalog entry. -/
structure Entry where
  tag      : String
  cue      : CueClass
  citation : String
  deriving Repr, Inhabited, DecidableEq

/-- Materialized catalog entries in source order. -/
def entriesList : List Entry := [
  ⟨"KGW", CueClass.greenListBias, "Kirchenbauer-Geipel-Wen 2023 — A Watermark for Large Language Models"⟩,
  ⟨"Aaronson", CueClass.pseudorandomSeq, "Aaronson 2022 — semi-private blog scheme, OpenAI internal"⟩,
  ⟨"ChristGunnZamir", CueClass.pseudorandomSeq, "Christ-Gunn-Zamir 2023 — Undetectable Watermarks for Language Models"⟩
]

end Unicode.Generated.WatermarkSchemes
