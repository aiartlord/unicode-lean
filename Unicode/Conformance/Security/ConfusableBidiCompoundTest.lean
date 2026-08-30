/-
  Unicode.Conformance.Security.ConfusableBidiCompoundTest

  Conformance certificate for the ConfusableBidiCompound detector (boundary
  layer: the cross-layer compound of identity spoofing and display deception).

  What this certifies.  The detector unites two spec clauses that are dangerous
  together in a way neither is alone.  UTS #39 §4 defines a confusable as a
  codepoint whose skeleton collides with another's — the machinery behind the
  IDN homograph, where a Cyrillic 'а' (U+0430) stands in for Latin 'a'.  UAX #9
  defines the bidirectional format controls — the overrides and isolates that
  reorder how text renders.  ConfusableBidiCompound fires only when a confusable
  codepoint co-occurs with a bidi override or isolate in the same input.

  Threat model.  An adversary registers a domain, username, or package name in
  which a homoglyph substitutes for an ASCII letter, then wraps the string in an
  RLO override or an LRI isolate so the rendered glyphs still spell a legitimate
  identifier.  The human reader sees `admin`; the resolver, comparator, or
  filter downstream sees a different byte sequence.  This is the Trojan-Source
  class, CVE-2021-42574: the visual layer and the identity layer disagree, and
  the disagreement is engineered to pass review.

  The discrimination it draws.  A lone confusable with no bidi control is left
  to the plain homoglyph detector and stays clear here, and a bidi override over
  ordinary ASCII is left to the RTL-injection detector and likewise stays clear.
  Only the simultaneous occurrence is a compound hazard, split by the class of
  bidi control present: an override-class control yields the high-severity
  `ConfusableInOverride`, while an isolate-class control yields the softer
  `ConfusableInIsolate`.

  How to read the certificate.  Each `Row` pairs a representative input with the
  classification `tag` its verdict must carry, where `none` denotes a clear
  verdict (a clear classification has no tag, so the tag field captures the
  clear-versus-hazard distinction as well as the hazard sub-class).  `verifyRow`
  recomputes `detect` and compares the tag; `all_rows_pass` discharges the whole
  table at once.  Appending a vector grows the proof obligation, so the covered
  threat surface can only expand and never silently regress.
-/

import Unicode.Security.Boundary.ConfusableBidiCompound
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.ConfusableBidiCompoundTest

open Unicode.Security.Boundary.ConfusableBidiCompound

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` codepoint sequence and the classification
    `tag` its verdict must carry, with `none` standing for a clear verdict. -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- A lone Cyrillic 'а' (U+0430) with no bidi control: confusable alone is
    -- the plain homoglyph detector's charter, so the compound stays clear here.
    { input := [0x0430], tag := none },
    -- RLO override (U+202E) then Cyrillic 'а': the canonical Trojan-Source plus
    -- IDN-homograph compound, and the discriminating case for the override arm.
    { input := [0x202E, 0x0430], tag := some "ConfusableInOverride" },
    -- LRI isolate (U+2066) then Greek 'ο' (U+03BF): a confusable inside an
    -- isolate rather than an override, exercising the softer isolate-class arm.
    { input := [0x2066, 0x03BF], tag := some "ConfusableInIsolate" } ]

/-- A row passes when `detect` reproduces the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the confusable table and
    the bidi-control classes demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/ConfusableBidiCompoundTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/ConfusableBidiCompoundTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x0061, 0x0064, 0x006D, 0x0069, 0x006E], "Clear", []⟩,
  ⟨[0x0430], "Clear", []⟩,
  ⟨[0x202E, 0x0041, 0x0042, 0x0043], "Clear", []⟩,
  ⟨[0x03B1, 0x03B2, 0x03B3], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x05D0, 0x05D1, 0x05D2], "Clear", []⟩,
  ⟨[0x0627, 0x0628, 0x0629], "Clear", []⟩,
  ⟨[0x3042, 0x3044, 0x3046], "Clear", []⟩,
  ⟨[0x202E, 0x0430], "Hazard:ConfusableInOverride", [1, 0]⟩,
  ⟨[0x0430, 0x0064, 0x006D, 0x0069, 0x006E, 0x202E], "Hazard:ConfusableInOverride", [0, 5]⟩,
  ⟨[0x202E, 0x03BF], "Hazard:ConfusableInOverride", [1, 0]⟩,
  ⟨[0x202D, 0x0410], "Hazard:ConfusableInOverride", [1, 0]⟩,
  ⟨[0x0078, 0x0430, 0x202C], "Hazard:ConfusableInOverride", [1, 2]⟩,
  ⟨[0x0061, 0x0064, 0x006D, 0x0069, 0x006E, 0x202E], "Hazard:ConfusableInOverride", [2, 5]⟩,
  ⟨[0x202B, 0x043E, 0x0070, 0x0065, 0x006E, 0x0430, 0x0069], "Hazard:ConfusableInOverride", [1, 0]⟩,
  ⟨[0x202D, 0x0410, 0x0042, 0x0043, 0x202C], "Hazard:ConfusableInOverride", [1, 0]⟩,
  ⟨[0x0430, 0x0064, 0x006D, 0x202E], "Hazard:ConfusableInOverride", [0, 3]⟩,
  ⟨[0x2066, 0x0430], "Hazard:ConfusableInIsolate", [1, 0]⟩,
  ⟨[0x2067, 0x0391], "Hazard:ConfusableInIsolate", [1, 0]⟩,
  ⟨[0x2068, 0x0430, 0x2069], "Hazard:ConfusableInIsolate", [1, 0]⟩,
  ⟨[0x2067, 0x0430, 0x0064, 0x006D, 0x0069, 0x006E, 0x2069], "Hazard:ConfusableInIsolate", [1, 0]⟩,
  ⟨[0x2068, 0x03BF, 0x2069], "Hazard:ConfusableInIsolate", [1, 0]⟩,
  ⟨[0x2066, 0x043E, 0x0070, 0x0435, 0x006E, 0x2069], "Hazard:ConfusableInIsolate", [1, 0]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "ConfusableBidiCompoundTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.ConfusableBidiCompoundTest
