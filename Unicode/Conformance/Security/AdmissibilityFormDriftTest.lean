/-
  Unicode.Conformance.Security.AdmissibilityFormDriftTest

  Conformance certificate for the AdmissibilityFormDrift detector (boundary layer,
  UTS #39 §3.1 General Security Profile for Identifiers, read against the
  compatibility normalization of UAX #15 §1.2 Normalization Form KC).

  What this harness certifies.  UTS #39 admits an identifier only when every one of
  its code points lies in the General Security Profile.  A system that admits a
  string in the form it was typed but then stores, compares, or displays the NFKC
  form of that same string is trusting two different strings under one decision.
  The AdmissibilityFormDrift detector composes the profile scan `isAllowedIdentifier`
  with `NFKC.toNFKC` and fires exactly when the admissibility verdict is not stable
  across that normalization step.

  Threat model.  An adversary submits an identifier that passes the admissibility
  check in the surface form yet normalizes to a materially different identifier, or
  vice versa.  Because compatibility decomposition folds ligatures apart and
  canonical composition fuses jamo runs into precomposed syllables, the pre- and
  post-NFKC code point sets can differ enough to cross the profile boundary — a
  spoofing and confusability vector against any registry, login, or access-control
  check that normalizes after it admits.

  The discrimination the detector draws.  A string whose admissibility is invariant
  under NFKC is sanctioned and reported clear; a string whose admissibility flips —
  in either direction — is hazardous and reported with the `AdmissibilityFormDrift`
  tag.  The vectors below pin both sides of that line: plain ASCII, which NFKC
  leaves untouched and which stays admissible, versus the ﬁ ligature and a
  decomposed Hangul-jamo run, each of which changes admissibility only because NFKC
  rewrites it.

  How to read the certificate.  Each theorem states the verdict the detector must
  draw on one documented vector.  The verdicts reason over the NFKC map, which does
  not reduce under `decide`, so each proof first rewrites the NFKC form away with a
  proven normalization witness (`toNFKC_id_of_starters`, `toNFKC_ligature_fi`,
  `toNFKC_jamo_han`) and then discharges the residual profile scan by `decide`.  The
  final theorem, `all_rows_pass`, bundles every vector into one conjunction; adding a
  vector extends that conjunction, so the guarantee this harness makes grows with the
  threat catalogue and cannot silently regress.
-/

import Unicode.Security.Boundary.AdmissibilityFormDrift

namespace Unicode.Conformance.Security.AdmissibilityFormDriftTest

open Unicode.Security.Boundary.AdmissibilityFormDrift

set_option maxRecDepth 100000

/-- The ASCII identifier "admin" lies wholly in the General Security Profile and is
    a fixed point of NFKC, so its admissibility cannot change across normalization;
    this is the negative control that proves the detector does not fire on the
    common case where surface form and normalized form coincide. -/
theorem admin_clear :
    (detect [0x61, 0x64, 0x6D, 0x69, 0x6E]).classify.isClear = true := by
  unfold detect
  rw [Unicode.Normalization.LowCodepointNfkc.toNFKC_id_of_starters
        [0x61, 0x64, 0x6D, 0x69, 0x6E] (by decide) (by decide)]
  decide

/-- The ﬁ ligature U+FB01 is outside the General Security Profile and so is not an
    admissible identifier on its own, yet its NFKC compatibility decomposition is the
    ASCII pair "fi", which is admissible; the admissibility verdict flips across
    normalization, so the detector must raise `AdmissibilityFormDrift` — the
    canonical single-code-point ligature spoofing vector. -/
theorem fi_ligature_drift :
    (detect [0xFB01]).classify.tag = some "AdmissibilityFormDrift" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFKC_ligature_fi]
  decide

/-- The conjoining Hangul jamos U+1112, U+1161, U+11AB each pass the per-code-point
    profile scan individually, but NFKC canonically composes the run into the single
    precomposed syllable 한, so the string admitted as a three-jamo sequence is not
    the string that will be stored or compared; the whole-string admissibility
    verdict changes and the detector must raise `AdmissibilityFormDrift` — the
    composition-side counterpart to the ligature vector. -/
theorem jamo_sequence_drift :
    (detect [0x1112, 0x1161, 0x11AB]).classify.tag
      = some "AdmissibilityFormDrift" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFKC_jamo_han]
  decide

/-- The complete certificate: every conformance vector above holds simultaneously.
    Appending a vector extends this conjunction, so the guarantee this harness makes
    grows with the threat catalogue and cannot silently regress. -/
theorem all_rows_pass :
    (detect [0x61, 0x64, 0x6D, 0x69, 0x6E]).classify.isClear = true ∧
    (detect [0xFB01]).classify.tag = some "AdmissibilityFormDrift" ∧
    (detect [0x1112, 0x1161, 0x11AB]).classify.tag
      = some "AdmissibilityFormDrift" :=
  ⟨admin_clear, fi_ligature_drift, jamo_sequence_drift⟩

end Unicode.Conformance.Security.AdmissibilityFormDriftTest
