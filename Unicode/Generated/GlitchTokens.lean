/-
  Unicode.Generated.GlitchTokens

  Curated inventory of "glitch tokens" — tokenizer-encoded
  strings that trigger anomalous behaviour in published LLMs.
  Source data lives in `Unicode/Ucd/Curated/GlitchTokens.txt`
  and is pinned in `Unicode/Ucd/Curated/SHA256SUMS`.

  Each entry is the raw UTF-8 byte sequence as it appears in the
  tokenizer's vocabulary; leading whitespace and capitalisation
  are part of the token identity and are preserved byte-exactly.

  Pre-staging table — no current detector consumes it; reserved
  for future X-family compositions involving model-tokenizer
  edge cases.
-/

namespace Unicode.Generated.GlitchTokens

/-- Raw text embedded at compile time. -/
def rawText : String := include_str "../Ucd/Curated/GlitchTokens.txt"

/-- Parse one line.  Returns `none` for blank lines or
    comment-only lines; returns `some line` (with leading
    whitespace preserved) for token lines.

    Comment detection looks at the trimmed line, but the
    returned token retains its original leading whitespace
    because that whitespace IS part of the token identity for
    most BPE vocabularies. -/
@[inline]
private def parseLine (line : String) : Option String :=
  let trimmed := (String.trimAscii line).toString
  if trimmed.isEmpty then none
  else if trimmed.startsWith "#" then none
  else some line

/-- The catalog of glitch tokens, in source-file order. -/
def tokens : Array String :=
  ((rawText.splitOn "\n").filterMap parseLine).toArray

theorem tokens_count : tokens.size = 39 := by native_decide

theorem solid_gold_present :
    tokens.contains " SolidGoldMagikarp" = true := by native_decide

theorem petertodd_present :
    tokens.contains " petertodd" = true := by native_decide

end Unicode.Generated.GlitchTokens
