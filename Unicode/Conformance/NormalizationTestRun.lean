/-
  Unicode.Conformance.NormalizationTestRun

  An evaluated run of the published `NormalizationTest.txt` against the four
  normalization forms, in the shape the other conformance runs use: parse every
  row, judge it, tally the judgements, and state how many rows were read.

  Each row is

      source;NFC;NFD;NFKC;NFKD; # comment

  and UAX #15 states the conformance conditions as equalities that must hold for
  every one of the five columns, not only for the source. Writing `c1` through
  `c5` for the columns:

      c2 == toNFC c1  == toNFC c2  == toNFC c3
      c3 == toNFD c1  == toNFD c2  == toNFD c3
      c4 == toNFKC c1 == toNFKC c2 == toNFKC c3 == toNFKC c4 == toNFKC c5
      c5 == toNFKD c1 == toNFKD c2 == toNFKD c3 == toNFKD c4 == toNFKD c5

  Each form is tallied separately, so a failure names which form disagreed
  rather than only that the row failed.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.NFKC
import Unicode.Normalization.NFKD

namespace Unicode.Conformance.NormalizationTestRun

open Unicode.Normalization.NFC (toNFC toNFD)
open Unicode.Normalization.NFKC (toNFKC)
open Unicode.Normalization.NFKD (toNFKD)

def trimS (s : String) : String := (String.trimAscii s).toString

def hexDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 48 && n ≤ 57 then n - 48
  else if n ≥ 65 && n ≤ 70 then n - 55
  else if n ≥ 97 && n ≤ 102 then n - 87
  else 0

def parseHexChars (cs : List Char) : Nat :=
  cs.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

def spaceFields (field : String) : List String :=
  ((trimS field).splitOn " ").filter (fun s => s ≠ "")

def hexList (field : String) : List Nat :=
  (spaceFields field).map (fun s => parseHexChars s.toList)

/-- The five codepoint columns of one row. -/
structure Row where
  source : List Nat
  nfc    : List Nat
  nfd    : List Nat
  nfkc   : List Nat
  nfkd   : List Nat
  deriving Inhabited

def normalizationTestRaw : String :=
  include_str "../Ucd/NormalizationTest.txt"

/-- Parse one line. Comment lines, the `@Part` headers and anything that is not
    five codepoint columns carry no row, which the `Option` chain expresses
    without a catch-all arm. -/
def parseRow (rawLine : String) : Option Row :=
  let body := (rawLine.takeWhile (fun c => c != '#')).toString
  let line := trimS body
  if line == "" then none
  else if line.startsWith "@" then none
  else
    let fields := line.splitOn ";"
    fields[0]?.bind fun c1 =>
    fields[1]?.bind fun c2 =>
    fields[2]?.bind fun c3 =>
    fields[3]?.bind fun c4 =>
    fields[4]?.bind fun c5 =>
      let src := hexList c1
      if src.isEmpty then none
      else
        some { source := src
               nfc := hexList c2
               nfd := hexList c3
               nfkc := hexList c4
               nfkd := hexList c5 }

def rows : List Row :=
  (normalizationTestRaw.splitOn "\n").filterMap parseRow

inductive Judgement where
  | pass
  | fail
  deriving Inhabited, DecidableEq

structure Tally where
  passed : Nat := 0
  failed : Nat := 0
  deriving Inhabited

def Tally.add (t : Tally) : Judgement → Tally
  | .pass => { t with passed := t.passed + 1 }
  | .fail => { t with failed := t.failed + 1 }

def Tally.line (t : Tally) (label : String) : String :=
  s!"  {label}: passed {t.passed}, failed {t.failed}, skipped 0"

def judgeOf (holds : Bool) : Judgement := if holds then .pass else .fail

/-- The four conformance conditions for one row, one judgement per form. -/
def judgeRow (r : Row) : Judgement × Judgement × Judgement × Judgement :=
  let cNFC :=
    toNFC r.source == r.nfc && toNFC r.nfc == r.nfc && toNFC r.nfd == r.nfc
  let cNFD :=
    toNFD r.source == r.nfd && toNFD r.nfc == r.nfd && toNFD r.nfd == r.nfd
  let cNFKC :=
    toNFKC r.source == r.nfkc && toNFKC r.nfc == r.nfkc && toNFKC r.nfd == r.nfkc
      && toNFKC r.nfkc == r.nfkc && toNFKC r.nfkd == r.nfkc
  let cNFKD :=
    toNFKD r.source == r.nfkd && toNFKD r.nfc == r.nfkd && toNFKD r.nfd == r.nfkd
      && toNFKD r.nfkc == r.nfkd && toNFKD r.nfkd == r.nfkd
  (judgeOf cNFC, judgeOf cNFD, judgeOf cNFKC, judgeOf cNFKD)

def talliesOf (sample : List Row) : Tally × Tally × Tally × Tally :=
  sample.foldl
    (fun (acc : Tally × Tally × Tally × Tally) r =>
      let (c, d, kc, kd) := judgeRow r
      (acc.1.add c, acc.2.1.add d, acc.2.2.1.add kc, acc.2.2.2.add kd))
    (default, default, default, default)

def firstFailIdxOf (sample : List Row) : Option Nat :=
  Prod.snd <| sample.foldl
    (fun (acc : Nat × Option Nat) r =>
      let (i, found) := acc
      if found.isSome then (i + 1, found)
      else
        let (c, d, kc, kd) := judgeRow r
        if c == .fail || d == .fail || kc == .fail || kd == .fail then (i + 1, some i)
        else (i + 1, none))
    (0, none)

def reportOn (sample : List Row) : String :=
  let (tC, tD, tKC, tKD) := talliesOf sample
  let head := s!"NormalizationTest: {sample.length} rows judged of {rows.length} published"
  let body :=
    String.intercalate "\n"
      [ tC.line "NFC", tD.line "NFD", tKC.line "NFKC", tKD.line "NFKD" ]
  match firstFailIdxOf sample with
  | none => head ++ "\n" ++ body
  | some i => head ++ "\n" ++ body ++ s!"\n  first failing row index: {i}"

def report : String := reportOn rows

def reportFirst (n : Nat) : String := reportOn (rows.take n)

end Unicode.Conformance.NormalizationTestRun
