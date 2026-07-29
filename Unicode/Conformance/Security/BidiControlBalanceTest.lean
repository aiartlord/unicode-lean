/-
  Unicode.Conformance.Security.BidiControlBalanceTest

  Conformance for the BidiControlBalance detector (Trojan-Source, CVE-2021-42574 /
  CVE-2021-42694). The detector walks a per-type bidi stack and classifies unbalanced
  embeddings, unbalanced isolates, orphan pops, and depth-exceeded nesting.

  Each theorem checks the full verdict — sub-threat tag together with the open/pop
  counts and orphan positions — on a documented CVE attack vector: the Trojan-Source
  RLO, the isolate-override, an orphan PDF, a 126-deep nesting, and a legitimate
  balanced RTL run.
-/

import Unicode.Security.Covert.BidiControlBalance

namespace Unicode.Conformance.Security.BidiControlBalanceTest

open Unicode.Security.Covert.BidiControlBalance

-- The depth-exceeded vector walks 252 codepoints; the fold recurses past the
-- default reducer budget (the detector module sets the same for its own check).
set_option maxRecDepth 1000000

/-- Trojan-Source RLO comment attack (CVE-2021-42574): the closing `)` is visually
    reordered by a lone RLO with no matching PDF. Unbalanced embedding: one opener,
    no pop. -/
theorem rlo_attack_verdict :
    let v := detect [0x69, 0x66, 0x20, 0x202E, 0x29, 0x7B]
    v.classify.tag = some "UnbalancedEmbedding"
      ∧ v.embOpenCount = 1 ∧ v.embPopCount = 0 := by decide

/-- Isolate-override attack (CVE-2021-42694): a lone LRI opens an isolate never
    closed by a PDI. Unbalanced isolate: one opener, no pop. -/
theorem lri_attack_verdict :
    let v := detect [0x2067, 0x41]
    v.classify.tag = some "UnbalancedIsolate"
      ∧ v.isoOpenCount = 1 ∧ v.isoPopCount = 0 := by decide

/-- Orphan pop: a lone PDF with no opener records exactly one orphan position (the
    stray pop at index 0). -/
theorem orphan_pdf_verdict :
    let v := detect [0x202C]
    v.classify.tag = some "OrphanPop" ∧ v.classify.positions = [0] := by decide

/-- Depth-exceeded DoS: 126 nested embeddings breach the UAX #9 §3.3.2 cap of 125.
    Reported as a whole-string verdict (empty positions; the `maxDepth` metadata
    carries the quantitative signal). -/
theorem depth_exceeded_verdict :
    let v := detect (List.replicate 126 0x202A ++ List.replicate 126 0x202C)
    v.classify.tag = some "DepthExceeded" ∧ v.classify.positions = [] := by decide

/-- Legitimate balanced RTL (RLE … PDF) is clear even though bidi controls are
    present, and the counts reflect the matched pair. -/
theorem balanced_rtl_clear :
    let v := detect [0x202B, 0x41, 0x202C]
    v.classify.isClear = true ∧ v.embOpenCount = 1 ∧ v.embPopCount = 1 := by decide

end Unicode.Conformance.Security.BidiControlBalanceTest
