/-
  Unicode.Generated.KnownAttackTargets

  Curated inventory of canonical names that have been the target
  of typosquat / homoglyph / supply-chain impersonation attempts
  in published security incidents.  Source data lives in
  `Unicode/Ucd/Curated/KnownAttackTargets.txt` and is pinned in
  `Unicode/Ucd/Curated/SHA256SUMS`.

  The `HomoglyphConfusable` detector consumes this set as the
  "ground truth" canonical-name list its UTS #39 §4
  skeleton-match should hit.  Each row's case is preserved as the
  legitimate package / brand publishes it; the per-name
  attribution lives in the spec doc, not the data file.
-/

import Unicode.Generated.KnownAttackTargetsData

namespace Unicode.Generated.KnownAttackTargets

set_option maxRecDepth 100000

/-- Raw text embedded at compile time. -/
def rawText : String := include_str "../Ucd/Curated/KnownAttackTargets.txt"

/-- Parse one line.  Returns `none` for blank or comment lines,
    `some name` for an entry line. -/
@[inline]
def parseLine (line : String) : Option String :=
  let t := (String.trimAscii line).toString
  if t.isEmpty then none
  else if t.startsWith "#" then none
  else some t

/-- The canonical attack-target names in source-file order. -/
def targetsParsed : List String :=
  ((rawText.splitOn "\n").filterMap parseLine)

/-- The materialized catalog, consumed downstream. -/
def targets : List String := targetsList

theorem targets_count : targets.length = 67 := by decide +kernel

-- Build-time drift gate.
#eval do
  unless targetsList == targetsParsed do
    throw (IO.userError "KnownAttackTargets drift: list ≠ parsed")

theorem react_present : targets.contains "react" = true := by decide +kernel

theorem Nethereum_present : targets.contains "Nethereum" = true := by
  decide +kernel

theorem paypal_present : targets.contains "paypal" = true := by decide +kernel

theorem openai_present : targets.contains "openai" = true := by decide +kernel

end Unicode.Generated.KnownAttackTargets
