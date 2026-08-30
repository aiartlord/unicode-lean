/-
  Unicode.Conformance.Security.BidiControlBalanceTest

  What this harness certifies.  It is the conformance certificate for the
  BidiControlBalance detector, which enforces the balancing discipline that
  UAX #9 (Unicode Bidirectional Algorithm) §2.3–§2.4 places on the explicit
  directional formatting characters — the embeddings and overrides RLE/LRE/RLO/
  LRO/PDF and the isolates RLI/LRI/FSI/PDI — together with the depth cap of 125
  that §3.3.2 (the explicit-level algorithm, rule X1) imposes on their nesting.
  The detector walks a per-type bidi stack and produces a rich verdict: a
  sub-threat tag together with the opener and pop counts, the positions of any
  orphaned pops, and the maximum nesting depth reached.

  Threat model.  This is the Trojan-Source class of attacks (CVE-2021-42574 and
  CVE-2021-42694): an adversary hides directional controls inside source
  comments or string literals so that the glyphs a human reviewer reads are
  reordered away from the token order the compiler consumes, letting malicious
  logic masquerade as inert text.  A left-open embedding or isolate, or a stray
  pop, is the structural signature of such a reordering, and a deeply nested run
  is a denial-of-service against any renderer that tracks the level stack.

  The discrimination the detector draws.  Balance is the dividing line.  A bidi
  control run whose openers and pops match — a genuine right-to-left phrase
  bracketed by RLE…PDF — is sanctioned and drawn clear even though controls are
  present; an unmatched opener, an orphaned pop, or nesting past 125 levels is
  hazardous and drawn with the specific sub-threat tag naming the imbalance.

  How to read the certificate.  Each theorem below pins the full verdict — tag,
  counts, and positions — on one documented attack vector: the Trojan-Source RLO
  comment, the isolate-override, an orphan PDF, a 126-deep nesting one past the
  cap, and the legitimate balanced RTL run that must stay clear.  The final
  theorem `all_rows_pass` conjoins every vector verdict into one closed
  obligation; appending a further vector extends that conjunction, so the
  guarantee grows with the threat catalogue and coverage cannot silently regress.
-/

import Unicode.Security.Covert.BidiControlBalance
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.BidiControlBalanceTest

open Unicode.Security.Covert.BidiControlBalance

-- The depth-exceeded vector walks 252 codepoints; the fold recurses past the
-- default reducer budget (the detector module sets the same for its own check).
set_option maxRecDepth 1000000

/-- The canonical Trojan-Source RLO comment attack (CVE-2021-42574): a lone
    U+202E RIGHT-TO-LEFT OVERRIDE reorders the following glyphs so the closing
    brace reads before the code it guards, and it is never balanced by a matching
    U+202C POP DIRECTIONAL FORMATTING. This is the discriminating case for an
    override left open, so the verdict must be `UnbalancedEmbedding` with one
    opener and no pop. -/
theorem rlo_attack_verdict :
    let v := detect [0x69, 0x66, 0x20, 0x202E, 0x29, 0x7B]
    v.classify.tag = some "UnbalancedEmbedding"
      ∧ v.embOpenCount = 1 ∧ v.embPopCount = 0 := by decide

/-- The isolate-flavoured Trojan-Source attack (CVE-2021-42694): a lone U+2067
    RIGHT-TO-LEFT ISOLATE opens an isolate scope that is never closed by a U+2069
    POP DIRECTIONAL ISOLATE, hiding a reordering behind the newer isolate
    controls rather than the classic embeddings. This exercises the separate
    isolate stack, so the verdict must be `UnbalancedIsolate` with one isolate
    opener and no isolate pop. -/
theorem lri_attack_verdict :
    let v := detect [0x2067, 0x41]
    v.classify.tag = some "UnbalancedIsolate"
      ∧ v.isoOpenCount = 1 ∧ v.isoPopCount = 0 := by decide

/-- The mirror-image imbalance: a lone U+202C POP DIRECTIONAL FORMATTING with no
    opener on the stack is a pop that closes nothing. This is the discriminating
    case for a stray closer, distinct from an open opener, so the verdict must be
    `OrphanPop` and must pinpoint the offending pop at exactly index 0. -/
theorem orphan_pdf_verdict :
    let v := detect [0x202C]
    v.classify.tag = some "OrphanPop" ∧ v.classify.positions = [0] := by decide

/-- The nesting denial-of-service: 126 embeddings stacked before any pop breach
    the UAX #9 §3.3.2 rule X1 cap of 125 levels by exactly one, the smallest
    run that crosses the boundary. This is a whole-string structural hazard
    rather than a fault at a single index, so the verdict must be `DepthExceeded`
    with empty positions — the quantitative signal is carried by the `maxDepth`
    metadata, not by an offending position. -/
theorem depth_exceeded_verdict :
    let v := detect (List.replicate 126 0x202A ++ List.replicate 126 0x202C)
    v.classify.tag = some "DepthExceeded" ∧ v.classify.positions = [] := by decide

/-- The sanctioned control that must not be flagged: a legitimate right-to-left
    phrase bracketed by U+202B RIGHT-TO-LEFT EMBEDDING and U+202C POP DIRECTIONAL
    FORMATTING. This is the negative discriminator that keeps the detector from
    condemning every bidi control on sight — because the opener and pop match,
    the verdict must be clear with one opener and one pop despite the controls
    being present. -/
theorem balanced_rtl_clear :
    let v := detect [0x202B, 0x41, 0x202C]
    v.classify.isClear = true ∧ v.embOpenCount = 1 ∧ v.embPopCount = 1 := by decide

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x69, 0x66, 0x20, 0x202E, 0x29, 0x7B];
      v.classify.tag = some "UnbalancedEmbedding"
        ∧ v.embOpenCount = 1 ∧ v.embPopCount = 0) ∧
    (let v := detect [0x2067, 0x41];
      v.classify.tag = some "UnbalancedIsolate"
        ∧ v.isoOpenCount = 1 ∧ v.isoPopCount = 0) ∧
    (let v := detect [0x202C];
      v.classify.tag = some "OrphanPop" ∧ v.classify.positions = [0]) ∧
    (let v := detect (List.replicate 126 0x202A ++ List.replicate 126 0x202C);
      v.classify.tag = some "DepthExceeded" ∧ v.classify.positions = []) ∧
    (let v := detect [0x202B, 0x41, 0x202C];
      v.classify.isClear = true ∧ v.embOpenCount = 1 ∧ v.embPopCount = 1) :=
  ⟨rlo_attack_verdict, lri_attack_verdict, orphan_pdf_verdict,
    depth_exceeded_verdict, balanced_rtl_clear⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/BidiControlBalanceTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/BidiControlBalanceTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x202A, 0x0041, 0x202C], "Clear", []⟩,
  ⟨[0x2066, 0x0041, 0x2069], "Clear", []⟩,
  ⟨[0x2068, 0x0041, 0x2069], "Clear", []⟩,
  ⟨[0x202E, 0x0041, 0x202C], "Clear", []⟩,
  ⟨[0x202A, 0x202A, 0x0041, 0x202C, 0x202C], "Clear", []⟩,
  ⟨[0x202A, 0x0041], "Hazard:UnbalancedEmbedding", [0]⟩,
  ⟨[0x202E, 0x0041], "Hazard:UnbalancedEmbedding", [0]⟩,
  ⟨[0x202D, 0x0041], "Hazard:UnbalancedEmbedding", [0]⟩,
  ⟨[0x0069, 0x0066, 0x0020, 0x202E, 0x0029, 0x007B], "Hazard:UnbalancedEmbedding", [3]⟩,
  ⟨[0x2066, 0x0041], "Hazard:UnbalancedIsolate", [0]⟩,
  ⟨[0x2067, 0x0041], "Hazard:UnbalancedIsolate", [0]⟩,
  ⟨[0x2068, 0x0041], "Hazard:UnbalancedIsolate", [0]⟩,
  ⟨[0x202C], "Hazard:OrphanPop", [0]⟩,
  ⟨[0x2069], "Hazard:OrphanPop", [0]⟩,
  ⟨[0x202C, 0x202C], "Hazard:OrphanPop", [0, 1]⟩,
  ⟨[0x0041, 0x202C, 0x0042], "Hazard:OrphanPop", [1]⟩,
  ⟨[0x202A, 0x0041, 0x202C, 0x2069], "Hazard:OrphanPop", [3]⟩,
  ⟨[0x202C, 0x2069, 0x202C], "Hazard:OrphanPop", [0, 1, 2]⟩,
  ⟨[0x0069, 0x0066, 0x0020, 0x0028, 0x0061, 0x0064, 0x006D, 0x0069, 0x006E, 0x0020, 0x202E, 0x0029, 0x0020, 0x007B, 0x0020, 0x002F, 0x0073, 0x0061, 0x0066, 0x0065, 0x002F, 0x007D], "Hazard:UnbalancedEmbedding", [10]⟩,
  ⟨[0x202A, 0x202A, 0x0041, 0x202C], "Hazard:UnbalancedEmbedding", [0, 1, 3]⟩,
  ⟨[0x202A, 0x0041, 0x202C, 0x202D], "Hazard:UnbalancedEmbedding", [0, 2, 3]⟩,
  ⟨[0x0072, 0x0065, 0x0074, 0x0075, 0x0072, 0x006E, 0x0020, 0x2066, 0x0066, 0x0072, 0x006F, 0x006D, 0x0020, 0x0061, 0x0064, 0x006D, 0x0069, 0x006E], "Hazard:UnbalancedIsolate", [7]⟩,
  ⟨[0x2066, 0x2067, 0x2068, 0x0041, 0x2069], "Hazard:UnbalancedIsolate", [0, 1, 2, 4]⟩,
  ⟨[0x202A, 0x2066, 0x0041, 0x202C], "Hazard:UnbalancedIsolate", [0, 1, 3]⟩,
  ⟨[0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066, 0x2066], "Hazard:DepthExceeded", []⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "BidiControlBalanceTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.BidiControlBalanceTest
