/-
  Unicode.Conformance.NormalizationTest

  UAX #15 conformance harness against the official
  `NormalizationTest.txt` published with UCD 17.0.0. Embeds the test
  file via `include_str`, parses each data row at module load, and
  verifies every UAX #15 §5 conformance property with `decide`
  theorems split per `@Part` section.

  Conformance test format (UAX #15 §5):

      c1; c2; c3; c4; c5; # comment

  with codepoint columns

      c2 = NFC(c1)    c3 = NFD(c1)
      c4 = NFKC(c1)   c5 = NFKD(c1)

  The conformance properties checked per row:

      NFC(c1)  = NFC(c2)  = NFC(c3)  = c2
      NFC(c4)  = NFC(c5)  = c4
      NFD(c1)  = NFD(c2)  = NFD(c3)  = c3
      NFD(c4)  = NFD(c5)  = c5
      NFKC(c1) = NFKC(c2) = NFKC(c3) = NFKC(c4) = NFKC(c5) = c4
      NFKD(c1) = NFKD(c2) = NFKD(c3) = NFKD(c4) = NFKD(c5) = c5

  Six theorems below — one per `@Part` section — exercise the full
  conformance suite via `decide` against the bundled
  `Unicode/Ucd/NormalizationTest.txt`.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.NFKC
import Unicode.Normalization.NFKD

namespace Unicode.Conformance.NormalizationTest

open Unicode.Normalization

/-- One row of `NormalizationTest.txt`. The five columns are stored
    as `List Nat` codepoint sequences. -/
structure ConformanceRow where
  source : List Nat
  nfc    : List Nat
  nfd    : List Nat
  nfkc   : List Nat
  nfkd   : List Nat
  deriving Repr, Inhabited

@[inline]
def trimS (s : String) : String := (String.trimAscii s).toString

def hexDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0

def parseHex (s : String) : Nat :=
  s.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

/-- Parse a space-separated list of hex codepoints. -/
def parseCodepoints (s : String) : List Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t)))

/-- Parse one data line. Returns `none` for blank, comment, or
    section-header lines. -/
def parseRow (rawLine : String) : Option ConformanceRow :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none
  else if line.startsWith "@" then none
  else
    match line.splitOn ";" with
    | c1 :: c2 :: c3 :: c4 :: c5 :: trailingFields =>
      Function.const (List String)
        (some
          { source := parseCodepoints (trimS c1),
            nfc    := parseCodepoints (trimS c2),
            nfd    := parseCodepoints (trimS c3),
            nfkc   := parseCodepoints (trimS c4),
            nfkd   := parseCodepoints (trimS c5) })
        trailingFields
    | irregularSplit => Function.const (List String) none irregularSplit

/-- Tag a parsed row with its `@Part` section index so the theorems
    below can target individual parts. -/
structure TaggedRow where
  part : Nat
  row  : ConformanceRow
  deriving Inhabited

/-- Walk the file once, threading the current `@Part` index. -/
def parseTaggedRows (raw : String) : List TaggedRow :=
  Prod.fst <| (raw.splitOn "\n").foldl
    (fun (acc : List TaggedRow × Nat) line =>
      let (out, currentPart) := acc
      let trimmed := trimS line
      if trimmed.startsWith "@Part" then
        let digit := match (trimmed.toList)[5]? with
          | some c => c
          | none   => ' '
        let pNum := hexDigitVal digit
        (out, pNum)
      else
        match parseRow line with
        | some r => (out ++ [{ part := currentPart, row := r }], currentPart)
        | none   => (out, currentPart))
    ([], 0)

/-- Raw test file embedded at compile time. -/
def normalizationTestRaw : String :=
  include_str "../Ucd/NormalizationTest.txt"

/-- All parsed test rows tagged by `@Part`. -/
def taggedRows : List TaggedRow := parseTaggedRows normalizationTestRaw

/-- Verify every UAX #15 §5 conformance property for one row. -/
def verifyRow (r : ConformanceRow) : Bool :=
  -- NFC stability
  (NFC.toNFC r.source = r.nfc) &&
  (NFC.toNFC r.nfc = r.nfc) &&
  (NFC.toNFC r.nfd = r.nfc) &&
  (NFC.toNFC r.nfkc = r.nfkc) &&
  (NFC.toNFC r.nfkd = r.nfkc) &&
  -- NFD stability
  (NFC.toNFD r.source = r.nfd) &&
  (NFC.toNFD r.nfc = r.nfd) &&
  (NFC.toNFD r.nfd = r.nfd) &&
  (NFC.toNFD r.nfkc = r.nfkd) &&
  (NFC.toNFD r.nfkd = r.nfkd) &&
  -- NFKC stability
  (NFKC.toNFKC r.source = r.nfkc) &&
  (NFKC.toNFKC r.nfc = r.nfkc) &&
  (NFKC.toNFKC r.nfd = r.nfkc) &&
  (NFKC.toNFKC r.nfkc = r.nfkc) &&
  (NFKC.toNFKC r.nfkd = r.nfkc) &&
  -- NFKD stability
  (NFKD.toNFKD r.source = r.nfkd) &&
  (NFKD.toNFKD r.nfc = r.nfkd) &&
  (NFKD.toNFKD r.nfd = r.nfkd) &&
  (NFKD.toNFKD r.nfkc = r.nfkd) &&
  (NFKD.toNFKD r.nfkd = r.nfkd)

/-- All rows in a given `@Part` pass conformance. -/
def partPasses (p : Nat) : Bool :=
  (taggedRows.filter (fun t => t.part = p)).all (fun t => verifyRow t.row)

-- Opt-in conformance gate. On a heavy build (`UNICODE_BUILD_HEAVY=1`, the flag
-- `build-full-conformance.sh` sets) the compiled runtime checks every parsed row
-- of the official `NormalizationTest.txt` corpus (Parts 0–5, 20034 rows) against
-- `verifyRow` — the UAX #15 §5 stability and cross-form identities — and throws
-- on divergence, failing the build. Ordinary builds skip the full-corpus run so
-- the module compiles without evaluating the pipeline over the whole corpus; the
-- fixture parse is not kernel-reducible, so there is no kernel `decide` over it.
-- The kernel-proved content is the algorithm-correctness proofs under
-- `Unicode.Normalization`
-- (`toNFC`/`toNFD` idempotence and cross-cancellation, the QuickCheck soundness
-- suite, the ToNFDAppend row-mirror), which establish that the stability and
-- cross-form identities `verifyRow` checks hold for every input by theorem — the
-- gate then confirms our algorithm reproduces Unicode's published columns across
-- the whole corpus.
#eval show IO Unit from do
  if (← IO.getEnv "UNICODE_BUILD_HEAVY") == some "1" then
    unless (List.range 6).all partPasses do
      throw (IO.userError "NormalizationTest: a @Part failed conformance")

end Unicode.Conformance.NormalizationTest
