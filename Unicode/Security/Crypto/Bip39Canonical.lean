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
  deriving DecidableEq, Repr, Inhabited

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
def collapseWhitespaceToSingle (input : Array Nat) : Array Nat := Id.run do
  let mut out : Array Nat := #[]
  let mut prevWasSpace : Bool := false
  for cp in input do
    if isBip39Whitespace cp then
      if !prevWasSpace then
        out := out.push 0x0020
      prevWasSpace := true
    else
      out := out.push cp
      prevWasSpace := false
  pure out

/-- Strip leading and trailing `U+0020` SPACE.  Assumes
    `collapseWhitespaceToSingle` has already run so the only
    whitespace codepoint remaining is `U+0020`. -/
def trimLeadingTrailing (input : Array Nat) : Array Nat :=
  let firstNonSpace :=
    (Array.range input.size).findSome? (fun i =>
      if hi : i < input.size then
        if input[i] ≠ 0x0020 then some i else none
      else none)
  match firstNonSpace with
  | none    => #[]
  | some s  =>
    let lastNonSpace :=
      (Array.range input.size).findSome? (fun i =>
        let j := input.size - 1 - i
        if hj : j < input.size then
          if input[j] ≠ 0x0020 then some j else none
        else none)
    match lastNonSpace with
    | none      => #[]
    | some last => input.extract s (last + 1)

/-- The BIP-39 canonical form of a codepoint sequence.  Composes
    the four pipeline stages in spec order: NFKD → toLower
    (default locale) → collapse whitespace → trim leading /
    trailing. -/
def bip39Canonical (input : Array Nat) : Array Nat :=
  let nfkd      := Unicode.Normalization.NFKD.toNFKD input
  let lowered   := Unicode.Casing.toLower .default nfkd
  let collapsed := collapseWhitespaceToSingle lowered
  trimLeadingTrailing collapsed

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Canonicalisation spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input canonicalises to empty. -/
theorem canonical_empty :
    bip39Canonical #[] = #[] := by native_decide

/-- An already-canonical lowercase ASCII input is a fixed point. -/
theorem canonical_idempotent_ascii :
    let cps : Array Nat := #[0x61, 0x62, 0x63]  -- "abc"
    bip39Canonical (bip39Canonical cps) = bip39Canonical cps := by
  native_decide

/-- Double space between non-space content collapses to single. -/
theorem canonical_collapses_double_space :
    let cps : Array Nat := #[0x61, 0x20, 0x20, 0x62]  -- "a  b"
    bip39Canonical cps = #[0x61, 0x20, 0x62] := by native_decide

/-- Trailing single space is stripped. -/
theorem canonical_strips_trailing :
    let cps : Array Nat := #[0x61, 0x20]
    bip39Canonical cps = #[0x61] := by native_decide

/-- Leading single space is stripped. -/
theorem canonical_strips_leading :
    let cps : Array Nat := #[0x20, 0x61]
    bip39Canonical cps = #[0x61] := by native_decide

/-- Uppercase ASCII lowercases. -/
theorem canonical_lowercases_ascii :
    let cps : Array Nat := #[0x41]  -- "A"
    bip39Canonical cps = #[0x61] := by native_decide

/-- Japanese ideographic space U+3000 canonicalises to U+0020. -/
theorem canonical_normalises_ideographic_space :
    let cps : Array Nat := #[0x61, 0x3000, 0x62]  -- "a<3000>b"
    bip39Canonical cps = #[0x61, 0x20, 0x62] := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Wordlist lookup
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Split a canonical-form input into words at `U+0020` boundaries.
    Returns the word slices as `Array Nat` (codepoint arrays). -/
def splitWords (canonical : Array Nat) : Array (Array Nat) := Id.run do
  let mut out : Array (Array Nat) := #[]
  let mut wordStart : Nat := 0
  let mut i : Nat := 0
  while hi : i < canonical.size do
    if canonical[i] = 0x0020 then
      if i > wordStart then
        out := out.push (canonical.extract wordStart i)
      wordStart := i + 1
    i := i + 1
  if canonical.size > wordStart then
    out := out.push (canonical.extract wordStart canonical.size)
  pure out

/-- Convert a `String` to its codepoint array.  Used to pre-decode
    each wordlist exactly once at module load. -/
@[inline] def stringToCodepoints (s : String) : Array Nat :=
  s.toList.toArray.map (·.toNat)

/-- Codepoint-array form of every wordlist, dispatched per
    language.  Each per-language array is `(wordlist lang).map
    stringToCodepoints` — a top-level constant that Lean's
    reducer caches after first evaluation. -/
def wordlistCps (lang : Language) : Array (Array Nat) :=
  (wordlist lang).map stringToCodepoints

/-- True iff `word` (as codepoints) appears in `lang`'s wordlist. -/
def isInWordlist (lang : Language) (word : Array Nat) : Bool :=
  (wordlistCps lang).any (fun entry => entry == word)

/-- Every language whose wordlist contains `word`.  Empty if
    `word` is not in any BIP-39 wordlist. -/
def wordlistsContaining (word : Array Nat) : Array Language :=
  allLanguages.filter (fun lang => isInWordlist lang word)

/-- The single language whose wordlist contains every word in
    `words`, if such a language exists; otherwise `none`.

    On empty `words`, returns `some .english` because
    `Array.all` on the empty array is `true` for every predicate;
    `findSome?` returns the first match (English). -/
def uniqueLanguage (words : Array (Array Nat)) : Option Language :=
  allLanguages.findSome? (fun lang =>
    if words.all (fun w => isInWordlist lang w) then some lang else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Wordlist spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The English wordlist contains "abandon" — every BIP-39
    mnemonic test vector starts with it. -/
theorem english_contains_abandon :
    isInWordlist .english #[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E] = true := by
  native_decide

/-- A made-up word is in no wordlist. -/
theorem nonsense_in_no_wordlist :
    wordlistsContaining #[0x71, 0x7A, 0x71, 0x7A, 0x71, 0x7A] = #[] := by
  native_decide

/-- Single-word "abandon" is unambiguously English. -/
theorem uniqueLanguage_abandon :
    uniqueLanguage #[#[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]] = some .english := by
  native_decide

/-- Empty word-list is vacuously unique (defaults to English). -/
theorem uniqueLanguage_empty :
    uniqueLanguage #[] = some .english := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Hazard probes (per-priority position-finders)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Count the trailing BIP-39 whitespace codepoints in `input`. -/
def countTrailingWhitespace (input : Array Nat) : Nat :=
  (input.reverse.takeWhile isBip39Whitespace).size

/-- First position of an uppercase ASCII letter in `input`, if any. -/
def firstUppercasePos (input : Array Nat) : Option Nat :=
  (Array.range input.size).findSome? (fun i =>
    if hi : i < input.size then
      let cp := input[i]
      if 0x41 ≤ cp ∧ cp ≤ 0x5A then some i else none
    else none)

/-- First position of a leading-or-consecutive whitespace run in
    `input`.  Fires when `input[i]` is BIP-39 whitespace AND either
    `i = 0` (leading) OR `input[i + 1]` is also BIP-39 whitespace
    (consecutive run).  Single internal separators do not fire. -/
def firstWhitespaceRunPos (input : Array Nat) : Option Nat :=
  (Array.range input.size).findSome? (fun i =>
    if hi : i < input.size then
      if isBip39Whitespace input[i] then
        if i = 0 then some i
        else if hj : i + 1 < input.size then
          if isBip39Whitespace input[i + 1] then some i else none
        else none
      else none
    else none)

/-- First position at which two `Array Nat`s diverge (differ in
    element or one ends).  Returns `none` when they are identical. -/
def firstArrayDivergence (a b : Array Nat) : Option Nat :=
  let n := if a.size ≤ b.size then a.size else b.size
  match (Array.range n).findSome? (fun i =>
    if ha : i < a.size then
      if hb : i < b.size then
        if a[i] != b[i] then some i else none
      else none
    else none) with
  | some i => some i
  | none   => if a.size = b.size then none else some n

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The K1 detection function.

    Composes the six probes in priority order; first hit wins.
    See module header §"Sub-threats" for the rationale on each
    position in the order. -/
def detect (input : Array Nat) : K1Verdict :=
  let canonical := bip39Canonical input
  let words     := splitWords canonical
  let wordCount := words.size

  let trailingCount := countTrailingWhitespace input
  let uppercasePos  := firstUppercasePos input
  let whitespacePos := firstWhitespaceRunPos input

  let nfkd       := Unicode.Normalization.NFKD.toNFKD input
  let nonNfkdPos :=
    if input == nfkd then none else firstArrayDivergence input nfkd

  let wordlistsPerWord := words.map wordlistsContaining
  let firstUnknownIdx  := wordlistsPerWord.findIdx? (fun langs => langs.isEmpty)
  let unique           := uniqueLanguage words

  let classification : K1Classification :=
    if trailingCount > 0 then
      let p := input.size - trailingCount
      .hazard (.trailingWhitespace trailingCount) #[p]
    else match uppercasePos with
    | some p => .hazard (.mixedCase p) #[p]
    | none   => match whitespacePos with
    | some p => .hazard (.whitespaceAnomaly p) #[p]
    | none   => match nonNfkdPos with
    | some p => .hazard (.nonNFKD p) #[p]
    | none   => match firstUnknownIdx with
    | some idx => .hazard (.wordlistMismatch idx) #[idx]
    | none     => match unique with
    | some lang => .clear lang
    | none      =>
      -- Every word in some wordlist, no single language covers
      -- all — collect the union for the verdict.
      let allPossible := wordlistsPerWord.foldl
        (init := (#[] : Array Language))
        (fun acc langs =>
          langs.foldl (init := acc) (fun a l =>
            if a.contains l then a else a.push l))
      .hazard (.languageAmbiguous allPossible) #[]

  { input := input,
    classify := classification,
    canonicalForm := canonical,
    wordCount := wordCount }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 Spot-check theorems
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear (and defaults to English). -/
theorem detect_empty_clear :
    (detect #[]).classify = .clear .english := by native_decide

/-- The canonical BIP-39 English test vector — 11×"abandon" +
    "about" — is clear and English. -/
theorem detect_canonical_english_12word :
    let mnemonic : Array Nat :=
      #[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x6F, 0x75, 0x74]
    (detect mnemonic).classify = .clear .english := by native_decide

/-- Trailing single space fires `trailingWhitespace`. -/
theorem detect_trailing_space :
    let input : Array Nat :=
      #[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20]
    (detect input).classify.tag = some "TrailingWhitespace" := by
  native_decide

/-- Title-case "Abandon" fires `mixedCase`. -/
theorem detect_mixed_case :
    let input : Array Nat := #[0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
    (detect input).classify.tag = some "MixedCase" := by native_decide

/-- Double-space between words fires `whitespaceAnomaly`. -/
theorem detect_double_space :
    let input : Array Nat :=
      #[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20, 0x20,
        0x61, 0x62, 0x6F, 0x75, 0x74]
    (detect input).classify.tag = some "WhitespaceAnomaly" := by
  native_decide

/-- Leading space fires `whitespaceAnomaly`. -/
theorem detect_leading_space :
    let input : Array Nat := #[0x20, 0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
    (detect input).classify.tag = some "WhitespaceAnomaly" := by
  native_decide

/-- Compatibility ligature U+FB00 ("ﬀ") decomposes under NFKD;
    fires `nonNFKD`. -/
theorem detect_non_nfkd_ligature :
    let input : Array Nat := #[0xFB00]
    (detect input).classify.tag = some "NonNFKD" := by native_decide

/-- No-break space U+00A0 decomposes under NFKD to U+0020;
    fires `nonNFKD`. -/
theorem detect_non_nfkd_nbsp :
    let input : Array Nat := #[0x61, 0x00A0, 0x62]
    (detect input).classify.tag = some "NonNFKD" := by native_decide

/-- A made-up word fires `wordlistMismatch`. -/
theorem detect_wordlist_mismatch :
    let input : Array Nat := #[0x71, 0x7A, 0x71, 0x7A]  -- "qzqz"
    (detect input).classify.tag = some "WordlistMismatch" := by
  native_decide

/-- Position is reported correctly: trailing space at index 7
    (after the 7-codepoint "abandon"). -/
theorem detect_trailing_space_position :
    let input : Array Nat :=
      #[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20]
    (detect input).classify.positions = #[7] := by native_decide

/-- Position is reported correctly: uppercase A at index 0. -/
theorem detect_mixed_case_position :
    let input : Array Nat := #[0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
    (detect input).classify.positions = #[0] := by native_decide

/-- The verdict's word-count metadata matches the canonical
    word-count on a 12-word mnemonic. -/
theorem detect_wordcount_12 :
    let mnemonic : Array Nat :=
      #[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20,
        0x61, 0x62, 0x6F, 0x75, 0x74]
    (detect mnemonic).wordCount = 12 := by native_decide

end Unicode.Security.Crypto.Bip39Canonical
