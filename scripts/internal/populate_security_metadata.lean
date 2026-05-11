/-
  scripts/internal/populate_security_metadata.lean

  One-shot fixture-rewriter that walks each `Unicode/Ucd/Security/*Test.txt`
  fixture, runs the matching `detect` against every row, and rewrites
  column 4 (the key-value attribution) with the metadata fields the
  conformance harness's `metadataMatches` predicate expects.

  Idempotent: re-running on a fully-populated fixture is a no-op (the
  emitted attribution string is byte-identical to what was already
  there).

  Invocation:

      lake env lean --run scripts/internal/populate_security_metadata.lean

  After running, regenerate SHA256SUMS via:

      ( cd Unicode/Ucd/Security && \
          sha256sum *.txt > SHA256SUMS )
-/

import Unicode.Security.Fixture
import Unicode.Security.Identity.EmojiZwjIntegrity
import Unicode.Security.Identity.SkinToneVariationForgery
import Unicode.Security.Display.FilenameDisguise
import Unicode.Security.Display.RtlInjection
import Unicode.Security.Display.RendererDivergence
import Unicode.Security.Form.NormalizationBomb
import Unicode.Security.Form.StreamSafeViolation
import Unicode.Security.Form.CaseExpansionMismatch
import Unicode.Security.Form.WidthClassConfusion
import Unicode.Security.Form.NfcIdempotenceWitness
import Unicode.Security.Boundary.IdentifierFormDrift
import Unicode.Security.Boundary.ConfusableBidiCompound
import Unicode.Security.Boundary.AdmissibilityFormDrift

open Unicode.Security.Calculus
open Unicode.Security.Fixture

namespace PopulateSecurityMetadata

/-- Format a single `Nat` codepoint as an uppercase hex token,
    matching the existing fixture convention (no `U+` prefix). -/
def hexCp (n : Nat) : String :=
  let raw := (Nat.toDigits 16 n).asString.toUpper
  raw

/-- Re-format an `Array Nat` of codepoints as the space-separated hex
    string the fixture column 1 uses. -/
def hexCps (a : Array Nat) : String :=
  String.intercalate " " (a.toList.map hexCp)

/-- Format a `Bool` as the lowercase string the fixture expects (so
    the harness's `checkBoolKey` accepts it). -/
def boolStr (b : Bool) : String := if b then "true" else "false"

/-- Decompose a fixture line into (data_prefix, trailing_comment).
    The trailing comment starts at the first `#` (which inside data
    rows always sits after column 5).  Returns `none` if the line is
    empty or starts with `#` (directives + blank lines pass through
    untouched). -/
def splitLine (line : String) : Option (String × String) :=
  let t := line.trimLeft
  if t.isEmpty || t.startsWith "#" then none
  else
    match line.splitOn "#" with
    | head :: rest => some (head, "#" ++ "#".intercalate rest)
    | []           => none

/-- Re-emit column 4 for a row.  `attrStr` should be of the form
    `key=value; key2=value2;` (no leading semicolon, includes the
    trailing one). -/
def rewriteDataPrefix (pre : String) (attrStr : String) : String :=
  match pre.splitOn ";" with
  | input :: cls :: pos :: _ =>
    let pieces : List String := [input.trimRight, " " ++ cls.trim, " " ++ pos.trim, " " ++ attrStr]
    "; ".intercalate (pieces.map (·.trim)) ++ "; "
  | _ => pre

/-- Lookup the per-family attribution string for a row. -/
def metaFor (family : String) (input : Array Nat) : String :=
  match family with
  | "I3" =>
    let v := Unicode.Security.Identity.EmojiZwjIntegrity.detect input
    s!"chain_len={v.chainLength}; zwj_count={v.zwjPositions.size}; \
       skin_tone_count={v.skinToneCount}; is_rgi={boolStr v.isRegisteredRGI};"
  | "I4" =>
    let v := Unicode.Security.Identity.SkinToneVariationForgery.detect input
    s!"skin_tone_count={v.skinToneCount}; vs15_count={v.variationSelector15Count}; \
       vs16_count={v.variationSelector16Count};"
  | "D2" =>
    let v := Unicode.Security.Display.FilenameDisguise.detect input
    s!"dot_count={v.dotPositions.size}; bidi_count={v.bidiControlCount}; \
       fw_in_ext={v.fullwidthInExt}; comb_in_ext={v.combiningInExt};"
  | "D3" =>
    let v := Unicode.Security.Display.RtlInjection.detect input
    s!"strong_rtl={v.strongRTLCount}; strong_ltr={v.strongLTRCount}; \
       bidi_count={v.bidiControlCount}; longest_run={v.longestRtlRunLen};"
  | "D4" =>
    let v := Unicode.Security.Display.RendererDivergence.detect input
    s!"vs_count={v.vsCount}; comb_count={v.combiningCount}; \
       fw_count={v.fullwidthCount}; has_zwj={boolStr v.hasZwj}; \
       ltr_count={v.strongLTRCount}; rtl_count={v.strongRTLCount};"
  | "F1" =>
    let v := Unicode.Security.Form.NormalizationBomb.detect input
    s!"nfd_len={v.nfdLen}; nfkd_len={v.nfkdLen}; \
       input_len={v.inputLen}; max_per_cp={v.maxPerCpExpansion};"
  | "F2" =>
    let v := Unicode.Security.Form.StreamSafeViolation.detect input
    s!"max_run={v.maxRunLen}; overruns={v.overrunCount}; \
       total_ns={v.totalNonStarters};"
  | "F4" =>
    let v := Unicode.Security.Form.CaseExpansionMismatch.detect input
    s!"upper_exp={v.upperExpansionCount}; lower_exp={v.lowerExpansionCount}; \
       max_exp={v.maxExpansionLen};"
  | "F5" =>
    let v := Unicode.Security.Form.WidthClassConfusion.detect input
    s!"fw_fold={v.fullwidthFoldCount}; hw_fold={v.halfwidthFoldCount};"
  | "F6" =>
    let v := Unicode.Security.Form.NfcIdempotenceWitness.detect input
    s!"nfc_len={v.nfcLen}; nfkc_len={v.nfkcLen};"
  | "X1" =>
    let v := Unicode.Security.Boundary.IdentifierFormDrift.detect input
    s!"shift_count={v.shiftCount};"
  | "X3" =>
    let v := Unicode.Security.Boundary.ConfusableBidiCompound.detect input
    s!"conf_count={v.confusableCount};"
  | "X4" =>
    let v := Unicode.Security.Boundary.AdmissibilityFormDrift.detect input
    s!"input_adm={boolStr v.inputAdmissible}; nfkc_adm={boolStr v.nfkcAdmissible};"
  | other => Function.const String "" other

/-- Top-level per-line rewriter.  `family` selects which detector to
    run; non-data lines (directives, blanks, full-line comments) are
    passed through unmodified. -/
def rewriteLine (family : String) (line : String) : String :=
  match splitLine line with
  | none             => line
  | some (pre, cmt)  =>
    let semis := pre.foldl (fun acc c => if c = ';' then acc + 1 else acc) 0
    if semis < 3 then line
    else
      let input := parseCodepointList (pre.splitOn ";").head!
      let attrStr := metaFor family input
      let newPrefix : String :=
        match pre.splitOn ";" with
        | a :: b :: c :: _ =>
          s!"{a.trimRight}; {b.trim}; {c.trim}; {attrStr} "
        | _ => pre
      newPrefix ++ cmt

/-- Rewrite one fixture in place. -/
def rewriteFile (family : String) (path : String) : IO Unit := do
  let raw <- IO.FS.readFile path
  let lines := raw.splitOn "\n"
  let rewritten := lines.map (rewriteLine family)
  let out := "\n".intercalate rewritten
  IO.FS.writeFile path out

def families : List (String × String) :=
  [ ("I3", "Unicode/Ucd/Security/EmojiZwjIntegrityTest.txt")
  , ("I4", "Unicode/Ucd/Security/SkinToneVariationForgeryTest.txt")
  , ("D2", "Unicode/Ucd/Security/FilenameDisguiseTest.txt")
  , ("D3", "Unicode/Ucd/Security/RtlInjectionTest.txt")
  , ("D4", "Unicode/Ucd/Security/RendererDivergenceTest.txt")
  , ("F1", "Unicode/Ucd/Security/NormalizationBombTest.txt")
  , ("F2", "Unicode/Ucd/Security/StreamSafeViolationTest.txt")
  , ("F4", "Unicode/Ucd/Security/CaseExpansionMismatchTest.txt")
  , ("F5", "Unicode/Ucd/Security/WidthClassConfusionTest.txt")
  , ("F6", "Unicode/Ucd/Security/NfcIdempotenceWitnessTest.txt")
  , ("X1", "Unicode/Ucd/Security/IdentifierFormDriftTest.txt")
  , ("X3", "Unicode/Ucd/Security/ConfusableBidiCompoundTest.txt")
  , ("X4", "Unicode/Ucd/Security/AdmissibilityFormDriftTest.txt")
  ]

end PopulateSecurityMetadata

def main : IO Unit := do
  for (family, path) in PopulateSecurityMetadata.families do
    IO.println s!"  populating {family} ← {path}"
    PopulateSecurityMetadata.rewriteFile family path
  IO.println "done."
