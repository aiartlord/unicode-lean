/-
  Unicode.Conformance.Security.CorpusDifferential

  The spec run over the shared verdict fixtures. Every port replays
  `fixtures/security/verdict_contract.json` and
  `fixtures/security/differential_corpus.json` byte for byte against verdicts
  the Rust reference produced; this module replays the same cases through
  `Unicode.Security.Policy.scan` and compares, so the recorded verdicts are
  held to the Lean and not only to the port that recorded them. A reference
  that localises a finding differently from the Lean, or picks a different
  rung, is a divergence here even when sixteen ports agree with it.

  Usage, from the repository root inside the Lean toolchain shell:

    lake env lean --run Unicode/Conformance/Security/CorpusDifferential.lean \
      fixtures/security/verdict_contract.json \
      fixtures/security/differential_corpus.json

  Exit status is the number of mismatching cases, capped at 255; every
  mismatch is printed with the case name, the recorded verdict and the Lean
  verdict in the wire shape.
-/

import Lean.Data.Json
import Unicode.Security.Policy

namespace Unicode.Conformance.Security.CorpusDifferential

open Lean (Json)
open Unicode.Security.Policy
open Unicode.Security.Calculus

/-- The wire projection of one finding: the six fields every port emits. -/
structure WireFinding where
  code      : String
  family    : String
  severity  : Nat
  positions : List Nat
  subThreat : Option String
  detail    : String
  deriving BEq, Repr, Inhabited

/-- The wire projection of one verdict: action plus findings; `normalized`
    is null for every plain `scan`. -/
structure WireVerdict where
  action   : String
  findings : List WireFinding
  deriving BEq, Repr, Inhabited

def wireOfFinding (f : Finding) : WireFinding :=
  { code := f.code, family := Family.slug f.family, severity := f.severity.toNat,
    positions := f.positions, subThreat := f.subThreat, detail := f.detail }

def wireOfVerdict (v : Verdict) : WireVerdict :=
  { action := v.action.tag, findings := v.findings.map wireOfFinding }

def allProfiles : List Profile :=
  [.gatewayHeader, .domainName, .dnsLabel, .url, .username, .displayName,
   .chatMessage, .sourceCode, .opaqueSecret, .binaryBlob]

def allModes : List Mode := [.observe, .warn, .enforce, .strict]

def profileOfTag? (s : String) : Option Profile := allProfiles.find? (fun p => p.tag = s)

def modeOfTag? (s : String) : Option Mode := allModes.find? (fun m => m.tag = s)

def natsOf (j : Json) : Except String (List Nat) := do
  let arr ← j.getArr?
  arr.toList.mapM (fun x => x.getNat?)

def optStrOf (j : Json) (key : String) : Except String (Option String) :=
  match j.getObjVal? key with
  | .ok .null => .ok none
  | .ok v => (v.getStr?).map some
  | .error e => .error e

def findingOf (j : Json) : Except String WireFinding := do
  let code ← (← j.getObjVal? "code").getStr?
  let family ← (← j.getObjVal? "family").getStr?
  let severity ← (← j.getObjVal? "severity").getNat?
  let positions ← natsOf (← j.getObjVal? "positions")
  let subThreat ← optStrOf j "sub_threat"
  let detail ← (← j.getObjVal? "detail").getStr?
  pure { code, family, severity, positions, subThreat, detail }

def verdictOf (j : Json) : Except String WireVerdict := do
  let action ← (← j.getObjVal? "action").getStr?
  let findingsJson ← (← j.getObjVal? "findings").getArr?
  let findings ← findingsJson.toList.mapM findingOf
  pure { action, findings }

def renderFinding (f : WireFinding) : String :=
  let sub := match f.subThreat with
    | some s => s
    | none => "null"
  s!"{f.code} sev={f.severity} pos={f.positions} sub={sub} detail={f.detail}"

def renderVerdict (v : WireVerdict) : String :=
  s!"action={v.action}\n" ++ String.intercalate "\n" (v.findings.map (fun f => "    " ++ renderFinding f))

/-- `none` when the Lean agrees with the recorded verdict, else the report. -/
def checkCase (j : Json) : Except String (Option String) := do
  let name ← (← j.getObjVal? "name").getStr?
  let profileTag ← (← j.getObjVal? "profile").getStr?
  let modeTag ← (← j.getObjVal? "mode").getStr?
  let input ← natsOf (← j.getObjVal? "input")
  let recorded ← verdictOf (← j.getObjVal? "verdict")
  let profile ← match profileOfTag? profileTag with
    | some p => pure p
    | none => throw s!"{name}: unknown profile {profileTag}"
  let mode ← match modeOfTag? modeTag with
    | some m => pure m
    | none => throw s!"{name}: unknown mode {modeTag}"
  let actual := wireOfVerdict (scan profile mode input)
  if actual == recorded then
    pure none
  else
    pure (some s!"{name} ({profileTag}, {modeTag}) input={input}\n  recorded: {renderVerdict recorded}\n  lean:     {renderVerdict actual}")

def runFile (path : String) : IO Nat := do
  let text ← IO.FS.readFile path
  let json ← match Json.parse text with
    | .ok j => pure j
    | .error e => throw (IO.userError s!"{path}: {e}")
  let cases ← match json.getObjVal? "cases" >>= Json.getArr? with
    | .ok arr => pure arr
    | .error e => throw (IO.userError s!"{path}: {e}")
  let mut mismatches := 0
  for c in cases do
    match checkCase c with
    | .ok none => pure ()
    | .ok (some report) =>
      mismatches := mismatches + 1
      IO.println s!"MISMATCH {report}"
    | .error e => throw (IO.userError s!"{path}: {e}")
  IO.println s!"{path}: {cases.size} cases, {mismatches} mismatch(es) against the Lean"
  pure mismatches

def main (args : List String) : IO UInt32 := do
  let mut total := 0
  for path in args do
    total := total + (← runFile path)
  if total = 0 then
    IO.println "clean: every recorded verdict is the Lean verdict"
  pure (UInt32.ofNat (min total 255))

end Unicode.Conformance.Security.CorpusDifferential

/-- Entry point for `lean --run`. -/
def main (args : List String) : IO UInt32 :=
  Unicode.Conformance.Security.CorpusDifferential.main args
