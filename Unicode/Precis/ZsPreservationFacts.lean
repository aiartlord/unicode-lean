/-
  Unicode.Precis.ZsPreservationFacts

  Heavy `decide +kernel` table facts for the "no non-ASCII Zs" preservation
  proofs, split out of `Unicode.Precis.ZsPreservation` so the expensive kernel
  reductions compile once into their own olean and the structural proof lemmas
  in `ZsPreservation` iterate without re-running them.
-/

import Unicode.Normalization.Decompose
import Unicode.Normalization.Hangul
import Unicode.Precis.ZsMapping

namespace Unicode.Precis.ZsPreservation

open Unicode.Normalization
open Unicode.Generated

set_option maxRecDepth 1000000

/-- Non-non-ASCII-Zs codepoints' canonical decompositions contain no
    non-ASCII Zs. -/
theorem nonNonAsciiZs_decomp_no_nonAsciiZs :
    UnicodeData.rows.all (fun row =>
      isNonAsciiZs row.codepoint ||
      row.canonicalDecomposition.all (fun d => !isNonAsciiZs d)) = true := by
  -- `rows.all` over the Array is quadratic under kernel reduction; prove it over
  -- the `List` mirror (linear, chunk-distributed) and transport to the Array.
  have h : UnicodeData.rowsList.all (fun row =>
      isNonAsciiZs row.codepoint ||
      row.canonicalDecomposition.all (fun d => !isNonAsciiZs d)) = true := by
    unfold UnicodeData.rowsList
    simp only [List.all_append]
    decide +kernel
  simpa [UnicodeData.rows, List.all_toArray] using h

-- The Hangul-decomposition "no non-ASCII Zs" facts are proven structurally in
-- `ZsPreservation` (`decomposeSyllable_output_no_nonAsciiZs`): the decomposition
-- formula places every output in the jamo block [0x1100, 0x11C2], disjoint from
-- every Zs codepoint, by `omega`. No 11172-syllable enumeration is needed.

/-- Every non-ASCII Zs codepoint `c` has a non-ASCII Zs in its
    `fullCanonicalDecompose` (either `c` itself when it has no
    decomposition, or a non-ASCII Zs among its decomposition targets).
    This anchors the `decompose_compose_inversion`-based argument that
    `toNFC` cannot introduce non-ASCII Zs. -/
theorem nonAsciiZs_fullDecompose_contains_nonAsciiZs :
    nonAsciiZsCodepoints.all (fun c =>
      (Decompose.fullCanonicalDecompose c).any isNonAsciiZs) = true := by
  decide +kernel

end Unicode.Precis.ZsPreservation
