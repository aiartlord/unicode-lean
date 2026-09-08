/-
  Unicode.Security.Identity.IntentionalConfusableCoverage

  Coverage certificate for the UTS #39 intentional confusables.

  `intentional.txt` lists the code-point pairs whose confusability the Unicode
  Consortium designates as intentional — cross-script look-alikes such as LATIN
  CAPITAL LETTER N and GREEK CAPITAL LETTER NU. The detector's case-folding
  skeleton alone does not unify all of them: case folding maps a capital
  look-alike to its lowercase form, and those diverge (ν confusable-maps to `v`,
  not `n`), so seventeen of the seventy-seven pairs keep distinct skeletons.

  `confusableCanonicalSkeleton` closes that gap. It maps each code point to the
  representative of its intentional-confusable class — the least code point in
  the class, which is the ASCII or lowest-Latin member — before taking the
  iterated UTS #39 skeleton. `canonicalRep` is the identity on ASCII and on every
  code point outside the classes, so it never rewrites an ordinary identifier; it
  only folds an exotic look-alike onto the letter it imitates.

  Because both members of a pair lie in one class, `canonicalRep` sends them to
  the same representative, so their canonical skeletons are the very same term.
  The certificate is therefore the light fact that every pair shares a
  representative, together with the congruence that a shared representative gives
  a shared canonical skeleton — no per-pair skeleton reduction is needed.
-/

import Unicode.Confusables
import Unicode.Generated.IntentionalConfusables

namespace Unicode.Security.Identity.IntentionalConfusableCoverage

open Unicode.Generated.IntentionalConfusables (pairs canonicalRep)
open Unicode.Confusables (iteratedSkeleton)

/-- The intentional-confusable-aware skeleton: fold each code point to its
    intentional-confusable class representative, then take the iterated UTS #39
    skeleton. -/
def confusableCanonicalSkeleton (cps : List Nat) : List Nat :=
  iteratedSkeleton (cps.map canonicalRep)

/-- Every UTS #39 intentional-confusable pair shares one class representative
    under `canonicalRep`. -/
theorem canonicalRep_unifies_intentional_pairs :
    pairs.all (fun p => canonicalRep p.fst == canonicalRep p.snd) = true := by
  decide +kernel

/-- A shared representative gives a shared canonical skeleton: the two singleton
    inputs map to the same list, so the iterated skeleton is the same term. -/
theorem confusableCanonicalSkeleton_singleton_eq {a b : Nat}
    (h : canonicalRep a = canonicalRep b) :
    confusableCanonicalSkeleton [a] = confusableCanonicalSkeleton [b] := by
  simp only [confusableCanonicalSkeleton, List.map_cons, List.map_nil, h]

/-- Both members of every intentional-confusable pair collapse to one canonical
    skeleton, so an identifier that differs from another only by an intentional
    substitution shares this canonical form and the detector catches it. -/
theorem intentional_pairs_unified (p : Nat × Nat) (hp : p ∈ pairs) :
    confusableCanonicalSkeleton [p.fst] = confusableCanonicalSkeleton [p.snd] := by
  have hall := canonicalRep_unifies_intentional_pairs
  rw [List.all_eq_true] at hall
  exact confusableCanonicalSkeleton_singleton_eq (by simpa using hall p hp)

end Unicode.Security.Identity.IntentionalConfusableCoverage
