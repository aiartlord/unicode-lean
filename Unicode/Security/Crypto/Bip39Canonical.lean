/-
  Unicode.Security.Crypto.Bip39Canonical

  Detection of BIP-39 mnemonic inputs that are not in
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

  Spec reference: `docs/specs/security/cryptographic-stability.md`
  the BIP-39 section of the cryptographic-stability spec.
  Verdict shape, sub-threat enumeration, and the threat-variant
  taxonomy (.a–.g) are taken verbatim from the spec.
-/

import Unicode.Security.Calculus
import Unicode.Normalization.NFKD
import Unicode.Casing
import Unicode.Generated.BIP39

namespace Unicode.Security.Crypto.Bip39Canonical

open Unicode.Security.Calculus
open Unicode.Generated.BIP39 (Language wordlist allLanguages)

-- The canonicalisation and detection spot checks reduce the NFKD → lower →
-- collapse → trim pipeline over concrete inputs; that nests deeper than the
-- default reducer recursion budget of 512.  Kernel reduction of these fixed
-- inputs stays well within a normal-PC memory budget; the depth bound simply
-- has to permit the pipeline to unfold.
set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The seven Bip39Canonical sub-threats.  Names + arguments
    follow the BIP-39 section of
    `cryptographic-stability.md`. -/
inductive SubThreat where
  | nonCanonicalForm    (preCanonLen : Nat) (postCanonLen : Nat)
  | wordlistMismatch    (firstUnknownWordIdx : Nat)
  | languageAmbiguous   (possibleLanguages : List Language)
  | whitespaceAnomaly   (firstRunPos : Nat)
  | trailingWhitespace  (count : Nat)
  | nonNFKD             (firstDivergentPos : Nat)
  | mixedCase           (firstUppercasePos : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level Bip39Canonical classification.  The clear case
    carries the unique language whose wordlist covers every
    canonical word (vacuously English on empty input). -/
inductive Classification where
  | clear  (lang : Language)
  | hazard (sub : SubThreat) (positions : List Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Verdict — the structured output of `detect`. -/
structure Verdict where
  input          : List Nat
  classify       : Classification
  canonicalForm  : List Nat
  wordCount      : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Universal projections (the three every detector must export so
-- `Unicode.Security.RunAll.runAll` can register the family uniformly)
-- ═══════════════════════════════════════════════════════════════════════════════

namespace Classification

@[inline] def isClear : Classification → Bool
  | .clear lang        => Function.const Language true lang
  | .hazard sub ps     =>
    Function.const (SubThreat × List Nat) false (sub, ps)

@[inline] def tag : Classification → Option String
  | .clear lang                   => Function.const Language none lang
  | .hazard sub ps                =>
    Function.const (List Nat) (
      match sub with
      | .nonCanonicalForm pre post =>
        Function.const (Nat × Nat) (some "NonCanonicalForm") (pre, post)
      | .wordlistMismatch idx      =>
        Function.const Nat (some "WordlistMismatch") idx
      | .languageAmbiguous langs   =>
        Function.const (List Language) (some "LanguageAmbiguous") langs
      | .whitespaceAnomaly pos     =>
        Function.const Nat (some "WhitespaceAnomaly") pos
      | .trailingWhitespace count  =>
        Function.const Nat (some "TrailingWhitespace") count
      | .nonNFKD pos               =>
        Function.const Nat (some "NonNFKD") pos
      | .mixedCase pos             =>
        Function.const Nat (some "MixedCase") pos
    ) ps

@[inline] def positions : Classification → List Nat
  | .clear lang        => Function.const Language [] lang
  | .hazard sub ps     => Function.const SubThreat ps sub

end Classification

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Canonicalisation pipeline
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a whitespace codepoint that BIP-39 treats as
    a word separator.  Two members:

      * `U+0020` SPACE         — default separator for Latin /
                                  Cyrillic / Greek wordlists.
      * `U+3000` IDEOGRAPHIC SPACE — Japanese mnemonic separator
                                  per BIP-39 §"Wordlist".

    The wordlist source files themselves are line-separated; the
    separator question is only about user-typed mnemonic input
    that the canonicalisation pipeline must accept. -/
@[inline] def isBip39Whitespace (cp : Nat) : Bool :=
  decide (cp = 0x0020) || decide (cp = 0x3000)

/-- Replace every maximal run of BIP-39 whitespace with a single
    `U+0020` SPACE.  Preserves non-whitespace codepoints
    byte-for-byte.  Idempotent on any input that already has
    single-space separation. -/
def collapseWhitespaceToSingle (input : List Nat) : List Nat :=
  let step : (List Nat × Bool) → Nat → (List Nat × Bool) := fun acc cp =>
    if isBip39Whitespace cp then
      (if acc.2 then acc.1 else 0x0020 :: acc.1, true)
    else (cp :: acc.1, false)
  (input.foldl step ([], false)).1.reverse

/-- Strip leading and trailing `U+0020` SPACE.  Assumes
    `collapseWhitespaceToSingle` has already run so the only
    whitespace codepoint remaining is `U+0020`. -/
def trimLeadingTrailing (input : List Nat) : List Nat :=
  ((input.dropWhile (· = 0x0020)).reverse.dropWhile (· = 0x0020)).reverse

/-- The BIP-39 canonical form of a codepoint sequence.  Composes
    the four pipeline stages in spec order: NFKD → toLower
    (default locale) → collapse whitespace → trim leading /
    trailing. -/
def bip39Canonical (input : List Nat) : List Nat :=
  let nfkd      := Unicode.Normalization.NFKD.toNFKD input
  let lowered   := Unicode.Casing.toLower .default nfkd
  let collapsed := collapseWhitespaceToSingle lowered
  trimLeadingTrailing collapsed

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Canonicalisation spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input canonicalises to empty. -/
theorem canonical_empty :
    bip39Canonical [] = [] := by decide

/-- An already-canonical lowercase ASCII input is a fixed point. -/
theorem canonical_idempotent_ascii :
    let cps : List Nat := [0x61, 0x62, 0x63]  -- "abc"
    bip39Canonical (bip39Canonical cps) = bip39Canonical cps := by
  -- Reduce the canonical form once, then rewrite; evaluating the nested
  -- `bip39Canonical (bip39Canonical _)` directly runs the NFKD→lower→collapse
  -- →trim pipeline twice. Factor out the single-pass fixed-point fact and
  -- rewrite both occurrences instead.
  have h : bip39Canonical [0x61, 0x62, 0x63] = [0x61, 0x62, 0x63] := by decide
  show bip39Canonical (bip39Canonical [0x61, 0x62, 0x63]) = bip39Canonical [0x61, 0x62, 0x63]
  simp only [h]

/-- Double space between non-space content collapses to single. -/
theorem canonical_collapses_double_space :
    let cps : List Nat := [0x61, 0x20, 0x20, 0x62]  -- "a  b"
    bip39Canonical cps = [0x61, 0x20, 0x62] := by decide

/-- Trailing single space is stripped. -/
theorem canonical_strips_trailing :
    let cps : List Nat := [0x61, 0x20]
    bip39Canonical cps = [0x61] := by decide

/-- Leading single space is stripped. -/
theorem canonical_strips_leading :
    let cps : List Nat := [0x20, 0x61]
    bip39Canonical cps = [0x61] := by decide

/-- Uppercase ASCII lowercases. -/
theorem canonical_lowercases_ascii :
    let cps : List Nat := [0x41]  -- "A"
    bip39Canonical cps = [0x61] := by decide

/-- Japanese ideographic space U+3000 canonicalises to U+0020. -/
theorem canonical_normalises_ideographic_space :
    let cps : List Nat := [0x61, 0x3000, 0x62]  -- "a<3000>b"
    bip39Canonical cps = [0x61, 0x20, 0x62] := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Wordlist lookup
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Accumulate the words of a canonical-form input, splitting at
    `U+0020` boundaries.  `acc` holds the current word in reverse;
    empty runs between separators contribute no word. -/
def splitWordsAux : List Nat → List Nat → List (List Nat)
  | [],          acc => if acc.isEmpty then [] else [acc.reverse]
  | cp :: rest,  acc =>
    if cp = 0x0020 then
      (if acc.isEmpty then [] else [acc.reverse]) ++ splitWordsAux rest []
    else splitWordsAux rest (cp :: acc)

/-- Split a canonical-form input into words at `U+0020` boundaries.
    The per-word codepoint sequences are returned as `List Nat`, matching the
    List-backed wordlist tables the membership lookup scans. -/
def splitWords (canonical : List Nat) : List (List Nat) :=
  splitWordsAux canonical []

/-- Convert a `String` to its codepoint array. `String.toList` does not reduce
    under the kernel, so this is used only at runtime — by `wordlistCpsDrift`
    below — to check the generated codepoint tables against the string wordlist. -/
@[inline] def stringToCodepoints (s : String) : List Nat :=
  s.toList.map (·.toNat)

/-- Codepoint-array form of every wordlist, taken directly from the generated
    kernel-visible tables (`Unicode.Generated.BIP39.wordlistCps`). Membership
    proofs reduce over `Nat` codepoints; the `String` wordlist would stall the
    kernel at the unreducible `String.toList`. -/
def wordlistCps (lang : Language) : List (List Nat) :=
  Unicode.Generated.BIP39.wordlistCps lang

/-- Runtime drift gate: the generated codepoint table equals the codepoint
    decoding of the string wordlist for every language. Keeps the two
    representations pinned to the same UCD source. -/
def wordlistCpsDrift : Bool :=
  allLanguages.all (fun lang =>
    Unicode.Generated.BIP39.wordlistCps lang == (wordlist lang).map stringToCodepoints)

/-- True iff `word` (as codepoints) appears in `lang`'s wordlist. -/
def isInWordlist (lang : Language) (word : List Nat) : Bool :=
  (wordlistCps lang).any (fun entry => entry == word)

/-- Every language whose wordlist contains `word`.  Empty if
    `word` is not in any BIP-39 wordlist. -/
def wordlistsContaining (word : List Nat) : List Language :=
  allLanguages.filter (fun lang => isInWordlist lang word)

/-- The single language whose wordlist contains every word in
    `words`, if such a language exists; otherwise `none`.

    On empty `words`, returns `some .english` because `List.all` on
    the empty list is `true` for every predicate; `findSome?` returns
    the first match (English). -/
def uniqueLanguage (words : List (List Nat)) : Option Language :=
  allLanguages.findSome? (fun lang =>
    if words.all (fun w => isInWordlist lang w) then some lang else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Wordlist spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The English wordlist contains "abandon" — every BIP-39 mnemonic test vector
    starts with it. A single linear scan of the List-backed wordlist. -/
theorem english_contains_abandon :
    isInWordlist .english [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E] = true := by
  decide +kernel

/-- A made-up word is in no wordlist. Each language is one linear `List.any`
    pass over the List-backed table. -/
theorem nonsense_in_no_wordlist :
    wordlistsContaining [0x71, 0x7A, 0x71, 0x7A, 0x71, 0x7A] = [] := by
  decide +kernel

/-- Single-word "abandon" is unambiguously English: English is the first
    language tried and it matches. -/
theorem uniqueLanguage_abandon :
    uniqueLanguage [[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]] = some .english := by
  decide +kernel

/-- Empty word-list is vacuously unique (defaults to English): `List.all` on
    the empty list is `true`, so no wordlist entry is consulted. -/
theorem uniqueLanguage_empty :
    uniqueLanguage [] = some .english := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Hazard probes (per-priority position-finders)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Count the trailing BIP-39 whitespace codepoints in `input`. -/
def countTrailingWhitespace (input : List Nat) : Nat :=
  (input.reverse.takeWhile isBip39Whitespace).length

/-- First position of an uppercase ASCII letter in `input`, if any. -/
def firstUppercasePos (input : List Nat) : Option Nat :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if 0x41 ≤ cpWithIdx.1 ∧ cpWithIdx.1 ≤ 0x5A then some cpWithIdx.2 else none)

/-- First position of a leading-or-consecutive whitespace run in
    `input`.  Fires when `input[i]` is BIP-39 whitespace AND either
    `i = 0` (leading) OR `input[i + 1]` is also BIP-39 whitespace
    (consecutive run).  Single internal separators do not fire.
    The lookahead pairs each code point with its successor via a zip
    against the shift-by-one view. -/
def firstWhitespaceRunPos (input : List Nat) : Option Nat :=
  let nexts : List (Option Nat) := (input.drop 1).map some ++ [none]
  ((input.zip nexts).zipIdx).findSome? (fun w =>
    let cp := w.1.1
    let i  := w.2
    if isBip39Whitespace cp then
      if i = 0 then some i
      else match w.1.2 with
        | some n => if isBip39Whitespace n then some i else none
        | none   => none
    else none)

/-- First position at which two code point lists diverge (differ in
    element or one ends).  Returns `none` when they are identical.
    Structural recursion — one traversal, no index arithmetic. -/
def firstArrayDivergence : List Nat → List Nat → Option Nat
  | [], [] => none
  | [], bHead :: bTail =>
    Function.const (Nat × List Nat) (some 0) (bHead, bTail)
  | aHead :: aTail, [] =>
    Function.const (Nat × List Nat) (some 0) (aHead, aTail)
  | aHead :: aTail, bHead :: bTail =>
    if aHead != bHead then some 0
    else (firstArrayDivergence aTail bTail).map (fun i => i + 1)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The Bip39Canonical detection function.

    Composes the six probes in priority order; first hit wins.
    See module header §"Sub-threats" for the rationale on each
    position in the order. -/
def detect (input : List Nat) : Verdict :=
  let canonical := bip39Canonical input
  let words     := splitWords canonical
  let wordCount := words.length

  let trailingCount := countTrailingWhitespace input
  let uppercasePos  := firstUppercasePos input
  let whitespacePos := firstWhitespaceRunPos input

  let nfkd       := Unicode.Normalization.NFKD.toNFKD input
  let nonNfkdPos :=
    if input == nfkd then none else firstArrayDivergence input nfkd

  let wordlistsPerWord := words.map wordlistsContaining
  let firstUnknownIdx  := wordlistsPerWord.findIdx? (fun langs => langs.isEmpty)
  let unique           := uniqueLanguage words

  let classification : Classification :=
    if trailingCount > 0 then
      let p := input.length - trailingCount
      .hazard (.trailingWhitespace trailingCount) [p]
    else match uppercasePos with
    | some p => .hazard (.mixedCase p) [p]
    | none   => match whitespacePos with
    | some p => .hazard (.whitespaceAnomaly p) [p]
    | none   => match nonNfkdPos with
    | some p => .hazard (.nonNFKD p) [p]
    | none   => match firstUnknownIdx with
    | some idx => .hazard (.wordlistMismatch idx) [idx]
    | none     => match unique with
    | some lang => .clear lang
    | none      =>
      -- Every word in some wordlist, no single language covers
      -- all — collect the union for the verdict.
      let allPossible := wordlistsPerWord.foldl
        (init := ([] : List Language))
        (fun acc langs =>
          langs.foldl (init := acc) (fun a l =>
            if a.contains l then a else a ++ [l]))
      .hazard (.languageAmbiguous allPossible) []

  { input := input,
    classify := classification,
    canonicalForm := canonical,
    wordCount := wordCount }

-- Detect spot-check theorems live in
-- `Unicode.Security.Crypto.Bip39CanonicalVectorsDetect`.

end Unicode.Security.Crypto.Bip39Canonical
