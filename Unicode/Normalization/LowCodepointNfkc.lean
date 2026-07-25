/-
  Unicode.Normalization.LowCodepointNfkc

  Compatibility composition (NFKC) is the identity on any all-starter sequence
  whose code points carry no compatibility decomposition and no canonical
  decomposition, and no two of which primary-compose:

      toNFKC cps = compose (reorder (compatDecomposeSequence cps)) = cps.

  This is the NFKC counterpart of `LowCodepointNfc.toNFC_id_of_starters`. The
  compatibility-decomposition stage differs from the canonical stage of NFC — it
  consults the sorted `CompatDecomp` table by binary search in addition to the
  canonical `UnicodeData` scan — so the identity carries one extra per-code-point
  hypothesis (`compatDecomposition cp = #[]`). That hypothesis is decidable by a
  handful of binary-search probes, so at a concrete call site it discharges with
  `by decide` without ever reducing the `UnicodeData` row scan, which is instead
  witnessed structurally against the below-U+00C0 bound reused from
  `LowCodepointNfc`.

  `toNFKC_id_of_starters` makes any ASCII (or non-compat-decomposing low-Latin)
  string's NFKC form a one-line corollary, in place of a per-string pipeline
  reduction that would exhaust the composition and row tables.
-/

import Unicode.Normalization.NFKC
import Unicode.Normalization.NFKD
import Unicode.Normalization.CompatDecompose
import Unicode.Normalization.LowCodepointNfc

namespace Unicode.Normalization.LowCodepointNfkc

open Unicode.Normalization Unicode.Normalization.LowCodepointNfc Unicode.Generated

set_option maxRecDepth 1000000

/-- Below U+00C0 there is no Hangul syllable decomposition: the syllable range
    starts far above, so the algorithmic branch misses by arithmetic. -/
theorem decomposeSyllable_none_lt (cp : Nat) (h : cp < 0xC0) :
    Hangul.decomposeSyllable? cp = none := by
  simp [Hangul.decomposeSyllable?, hsyl_false_lt cp h]

/-- One fuel step: a below-U+00C0 code point with no compatibility decomposition
    is terminal on every branch — not a Hangul syllable, no canonical
    decomposition (witnessed by the below-U+00C0 row bound), no compatibility
    decomposition (supplied). -/
theorem fcdFuel_id_lt (fuel cp : Nat) (h : cp < 0xC0)
    (hCompat : CompatDecompose.compatDecomposition cp = #[]) :
    CompatDecompose.fullCompatDecomposeFuel (fuel + 1) cp = #[cp] := by
  rw [CompatDecompose.fullCompatDecomposeFuel.eq_def]
  simp [decomposeSyllable_none_lt cp h, dec_lt cp h, hCompat]

/-- A below-U+00C0 code point with no compatibility decomposition fully
    compat-decomposes to itself. -/
theorem fullCompatDecompose_id_lt (cp : Nat) (h : cp < 0xC0)
    (hCompat : CompatDecompose.compatDecomposition cp = #[]) :
    CompatDecompose.fullCompatDecompose cp = #[cp] := by
  unfold CompatDecompose.fullCompatDecompose CompatDecompose.maxDepth
  exact fcdFuel_id_lt 31 cp h hCompat

/-- Compatibility decomposition of a sequence is the identity when each code
    point compat-decomposes to itself. -/
theorem compatDecomposeSequence_id (cps : List Nat)
    (h : ∀ cp ∈ cps, CompatDecompose.fullCompatDecompose cp = #[cp]) :
    CompatDecompose.compatDecomposeSequence cps = cps := by
  unfold CompatDecompose.compatDecomposeSequence
  exact NFD.flatMap_concat_id_of_all_singleton
    CompatDecompose.fullCompatDecompose cps h

/-- **NFKD is the identity on an all-starter, non-decomposing sequence.** The
    canonical branch discharges against the below-U+00C0 row bound; the
    compatibility branch against the supplied per-code-point facts; the reorder
    stage is vacuous on all starters. -/
theorem toNFKD_id_of_starters (cps : List Nat)
    (hCompat : ∀ cp ∈ cps, CompatDecompose.compatDecomposition cp = #[])
    (hLt : ∀ cp ∈ cps, cp < 0xC0) :
    NFKD.toNFKD cps = cps := by
  unfold NFKD.toNFKD
  rw [compatDecomposeSequence_id cps
        (fun cp hMem => fullCompatDecompose_id_lt cp (hLt cp hMem) (hCompat cp hMem)),
      Reorder.reorder_id_on_HasSortedRuns cps
        (hsr_of_all_ccc0 cps
          (fun cp hMem => cccz cp (hLt cp hMem)))]

/-- **NFKC is the identity on an all-starter, non-decomposing, non-composing
    sequence.** The decompose+reorder prefix reduces to the input via
    `toNFKD_id_of_starters`; the compose stage is the identity because no
    adjacent starter pair primary-composes below U+00C0. -/
theorem toNFKC_id_of_starters (cps : List Nat)
    (hCompat : ∀ cp ∈ cps, CompatDecompose.compatDecomposition cp = #[])
    (hLt : ∀ cp ∈ cps, cp < 0xC0) :
    NFKC.toNFKC cps = cps := by
  unfold NFKC.toNFKC
  rw [toNFKD_id_of_starters cps hCompat hLt,
      Compose.compose_id_of_shift cps
        (fun cp hMem => cccz cp (hLt cp hMem))
        (noAdj_all_lt cps (fun cp hMem => hLt cp hMem))]

end Unicode.Normalization.LowCodepointNfkc
