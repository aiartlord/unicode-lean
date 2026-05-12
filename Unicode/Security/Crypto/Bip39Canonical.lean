/-
  Unicode.Security.Crypto.Bip39Canonical

  K1 — Detection of BIP-39 mnemonic inputs that are not in
  canonical form or whose words do not all belong to a single
  BIP-39 wordlist.

  Threat model.  Tier A₁ (local injector).  A user types a
  recovery mnemonic; if the canonical form differs from the
  typed bytes, the seed derived by BIP-39's PBKDF2-HMAC-SHA512
  pipeline will not match what the wallet expects.  Wallet
  recovery silently fails or derives a different wallet —
  funds become irrecoverable.

  Canonical form (BIP-39 specification §"Wordlist", also in the
  Trezor and Ledger reference implementations):

      bip39Canonical input =
        input
          |> NFKD
          |> toLower (default locale)
          |> collapseWhitespaceToSingle (U+0020)
          |> trimLeadingTrailing

  Plus: every whitespace-separated word in the canonical form
  must belong to exactly one BIP-39 wordlist (ten supported
  languages — English, Japanese, Korean, Spanish, Chinese
  Simplified, Chinese Traditional, French, Italian, Czech,
  Portuguese).

  Sub-threats (priority order, first-hit wins):

    1. `trailingWhitespace`   — input ends with whitespace.
       Easiest user-fixable mistake; lifted to top so the
       canonical-form witness reports the most-actionable
       hazard first.
    2. `mixedCase`            — input contains uppercase ASCII.
       BIP-39 wordlists are lowercase by spec; any uppercase
       letter would canonicalise away and produce a different
       hashed seed.
    3. `whitespaceAnomaly`    — pre-canonical input has at
       least one run of two-or-more consecutive whitespace
       codepoints (leading or internal).  Trailing runs are
       handled by `trailingWhitespace` first.
    4. `nonNFKD`              — input is not in NFKD form.
       Any precomposed character whose NFKD differs (combining
       marks, compatibility ligatures, full-width characters).
    5. `wordlistMismatch`     — at least one canonical word
       is not present in any BIP-39 wordlist.  Either a typo
       or an attacker-substituted token.
    6. `languageAmbiguous`    — every canonical word appears
       in some wordlist, but no single wordlist contains all
       of them.  The classic Spanish-Italian-collision shape.
    7. `nonCanonicalForm`     — catch-all when canonical
       differs from the input but no specific sub-threat
       matched (e.g. leading single space, no other anomaly).
       Reports the byte-count drift in either direction.
    8. clear(language)        — every canonical word is in
       `language`'s wordlist and no anomaly fired.

  Spec reference: `docs/specs/security/L6-cryptographic-stability.md`
  §K1.  Verdict shape, sub-threat enumeration, and threat-variant
  taxonomy K1.a–K1.g are taken verbatim from §K1.3.
-/

import Unicode.Security.Calculus
import Unicode.Normalization.NFKD
import Unicode.Casing
import Unicode.Generated.BIP39

namespace Unicode.Security.Crypto.Bip39Canonical

open Unicode.Security.Calculus
open Unicode.Generated.BIP39 (Language wordlist allLanguages)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The seven K1 sub-threats.  Names + arguments follow
    `L6-cryptographic-stability.md` §K1.3. -/
inductive K1SubThreat where
  | nonCanonicalForm    (preCanonLen : Nat) (postCanonLen : Nat)
  | wordlistMismatch    (firstUnknownWordIdx : Nat)
  | languageAmbiguous   (possibleLanguages : Array Language)
  | whitespaceAnomaly   (firstRunPos : Nat)
  | trailingWhitespace  (count : Nat)
  | nonNFKD             (firstDivergentPos : Nat)
  | mixedCase           (firstUppercasePos : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level K1 classification.  The clear case carries the
    unique language whose wordlist covers every canonical word
    (vacuously English on empty input). -/
inductive K1Classification where
  | clear  (lang : Language)
  | hazard (sub : K1SubThreat) (positions : Array Nat)
  deriving Inhabited

/-- K1 verdict — the structured output of `detect`. -/
structure K1Verdict where
  input          : Array Nat
  classify       : K1Classification
  canonicalForm  : Array Nat
  wordCount      : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Universal projections (the three every detector must export so
-- `Unicode.Security.RunAll.runAll` can register the family uniformly)
-- ═══════════════════════════════════════════════════════════════════════════════

namespace K1Classification

@[inline] def isClear : K1Classification → Bool
  | .clear _lang        => true
  | .hazard _sub _ps    => false

@[inline] def tag : K1Classification → Option String
  | .clear _lang                  => none
  | .hazard sub _ps               =>
    match sub with
    | .nonCanonicalForm _pre _post  => some "NonCanonicalForm"
    | .wordlistMismatch _idx        => some "WordlistMismatch"
    | .languageAmbiguous _langs     => some "LanguageAmbiguous"
    | .whitespaceAnomaly _pos       => some "WhitespaceAnomaly"
    | .trailingWhitespace _count    => some "TrailingWhitespace"
    | .nonNFKD _pos                 => some "NonNFKD"
    | .mixedCase _pos               => some "MixedCase"

@[inline] def positions : K1Classification → Array Nat
  | .clear _lang        => #[]
  | .hazard _sub ps     => ps

end K1Classification

end Unicode.Security.Crypto.Bip39Canonical
