/-
  Unicode.Generated.KnownAttackTargets

  Curated inventory of canonical names that have been the target
  of typosquat / homoglyph / supply-chain impersonation attempts
  in published security incidents.  Source data lives in
  `Unicode/Ucd/Curated/KnownAttackTargets.txt` and is pinned in
  `Unicode/Ucd/Curated/SHA256SUMS`.

  The I1 HomoglyphConfusable detector consumes this set as the
  "ground truth" canonical-name list its skeleton-match should
  hit.  Curation policy and the per-name attribution live in
  `docs/specs/security/L2-identity-spoofing.md`.

  Pre-staging table — no current detector consumes it directly;
  reserved for future expansions of I1 and for the deferred
  Layer-6 K1 family.
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

/-- The canonical attack-target names, lower-case ASCII, in
    source-file order. -/
def targets : Array String :=
  ((rawText.splitOn "\n").filterMap parseLine).toArray

theorem targets_count : targets.size = 48 := by native_decide

theorem react_present : targets.contains "react" = true := by native_decide

theorem nethereum_present : targets.contains "nethereum" = true := by
  native_decide

end Unicode.Generated.KnownAttackTargets
