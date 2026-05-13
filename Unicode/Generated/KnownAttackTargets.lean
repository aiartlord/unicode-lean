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

namespace Unicode.Generated.KnownAttackTargets

/-- Raw text embedded at compile time. -/
def rawText : String := include_str "../Ucd/Curated/KnownAttackTargets.txt"

/-- Parse one line.  Returns `none` for blank or comment lines,
    `some name` for an entry line. -/
@[inline]
private def parseLine (line : String) : Option String :=
  let t := (String.trimAscii line).toString
  if t.isEmpty then none
  else if t.startsWith "#" then none
  else some t

/-- The canonical attack-target names in source-file order. -/
def targets : Array String :=
  ((rawText.splitOn "\n").filterMap parseLine).toArray

theorem targets_count : targets.size = 67 := by native_decide

theorem react_present : targets.contains "react" = true := by native_decide

theorem Nethereum_present : targets.contains "Nethereum" = true := by
  native_decide

theorem paypal_present : targets.contains "paypal" = true := by native_decide

theorem openai_present : targets.contains "openai" = true := by native_decide

end Unicode.Generated.KnownAttackTargets
