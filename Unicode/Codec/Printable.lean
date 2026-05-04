/-
  Unicode.Codec.Printable

  Tier-2 text predicate for human-readable content. Every byte
  passes four checks in order:

    1. Structural UTF-8 validity (rejects overlong, surrogate,
       beyond-max, truncated, and bare-continuation sequences).
    2. No C0 control byte except HT (U+0009) and LF (U+000A), and
       no DEL (U+007F). CR (U+000D) is rejected; callers ingesting
       Windows-origin content normalise CRLF upstream.
    3. No forbidden codepoint. Two tiers:
         * Narrow CVE-flagged blocklist — bidi overrides
           (U+202A..U+202E), bidi isolates (U+2066..U+2069),
           zero-widths (U+200B..U+200F), BOM (U+FEFF), tag
           characters (U+E0000..U+E007F), variation selectors
           (U+FE00..U+FE0F and U+E0100..U+E01EF), Hangul fillers
           (U+FFA0, U+3164), soft hyphen (U+00AD), interlinear
           annotation controls (U+FFF9..U+FFFB), Mongolian vowel
           separator (U+180E).
         * Default_Ignorable_Code_Point residual — every codepoint
           flagged `Default_Ignorable_Code_Point` by UCD 17.0 that
           is not already covered by the narrow tier.
    4. Content is in Unicode Normalization Form C. Non-NFC input
       is rejected, never silently normalised — silent normalisation
       would mask the fact that the source was malformed.

  Three layers exposed:

    * `isPrintableUtf8Bytes` — Boolean validity predicate.
    * `PrintableUtf8 maxBytes` — refinement type.
    * `PrintableUtf8.ofBytes?` — smart constructor.

  Strict-cohesion (StrictBox + RejectReason) and any wire-format
  framing are downstream concerns; this module owns only the
  specification predicate, the categorical classification, the
  refinement type, and the constructor.
-/

import Unicode.Codec.Strict
import Unicode.Codec.Utf8
import Unicode.Generated.DerivedCoreProperties
import Unicode.Normalization.Utf8Bridge

namespace Unicode.Codec.Printable

open Unicode.Codec.Strict (ForbiddenCategory)
open Unicode.Codec.Utf8 (firstInvalidUtf8Offset foldCodepointsWithOffset)
open Unicode.Generated
open Unicode.Normalization

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 CONTROL-BYTE PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A byte is "forbidden control" if it is a C0 control other than
    HT (U+0009) and LF (U+000A), or if it is DEL (U+007F). CR
    (U+000D) falls under C0 and is rejected; callers should
    normalise CRLF upstream when ingesting Windows-origin content. -/
def isForbiddenControlByte (b : UInt8) : Bool :=
  decide ((b.toNat < 0x20 ∧ b.toNat ≠ 0x09 ∧ b.toNat ≠ 0x0A) ∨ b.toNat = 0x7F)

theorem isForbiddenControlByte_NUL : isForbiddenControlByte 0x00 = true := by decide
theorem isForbiddenControlByte_HT  : isForbiddenControlByte 0x09 = false := by decide
theorem isForbiddenControlByte_LF  : isForbiddenControlByte 0x0A = false := by decide
theorem isForbiddenControlByte_CR  : isForbiddenControlByte 0x0D = true := by decide
theorem isForbiddenControlByte_DEL : isForbiddenControlByte 0x7F = true := by decide
theorem isForbiddenControlByte_A   : isForbiddenControlByte 0x41 = false := by decide
theorem isForbiddenControlByte_hi  : isForbiddenControlByte 0xFF = false := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 FORBIDDEN-CONTROL WALKER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Byte offset + offending byte of the first forbidden control byte
    in `bs`, or `none` if none is present. -/
def firstForbiddenControlFrom (bs : ByteArray) (i : Nat) : Option (Nat × UInt8) :=
  if hi : i < bs.size then
    let b := bs[i]'hi
    if isForbiddenControlByte b then some (i, b)
    else firstForbiddenControlFrom bs (i + 1)
  else none
termination_by bs.size - i

def firstForbiddenControl (bs : ByteArray) : Option (Nat × UInt8) :=
  firstForbiddenControlFrom bs 0

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 FORBIDDEN-CODEPOINT CLASSIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

-- The categorical label for the curated CVE-flagged blocklist is
-- `Unicode.Codec.Strict.ForbiddenCategory`. It is shared with every
-- strict text codec under `Unicode.Codec.*` so reject paths agree on a
-- single vocabulary; the `open Unicode.Codec.Strict (ForbiddenCategory)`
-- above pulls it into the local namespace.

/-- Outcome of classifying a codepoint against the printable-text
    rejection rules. Two tiers: `narrow` for the curated CVE-flagged
    list (carries the specific category), `defaultIgnorable` for the
    UCD 17.0 `Default_Ignorable_Code_Point` residual. -/
inductive ForbiddenClassification where
  | narrow (category : ForbiddenCategory)
  | defaultIgnorable
  deriving Repr, DecidableEq, Inhabited

/-- `Default_Ignorable_Code_Point` membership per UCD 17.0. The
    narrow categories below are all DICP-subsets; this predicate is
    consulted AFTER the narrow list so the narrow tier always wins
    on overlapping codepoints. -/
def isDefaultIgnorableCodepoint (cp : Nat) : Bool :=
  DerivedCoreProperties.defaultIgnorable.any
    (fun lh => decide (lh.fst ≤ cp ∧ cp ≤ lh.snd))

/-- Classify a codepoint against the printable-text rejection rules.
    Returns `some (.narrow cat)` for a CVE-flagged class,
    `some .defaultIgnorable` for a DICP residual, `none` otherwise.

    Order is load-bearing: the narrow categories are checked first
    so the most specific category wins; DICP catches everything else
    flagged `Default_Ignorable_Code_Point`. -/
def classifyCodepointIfForbidden (cp : Nat) : Option ForbiddenClassification :=
  if 0x202A ≤ cp ∧ cp ≤ 0x202E then some (.narrow .bidiOverride)
  else if 0x2066 ≤ cp ∧ cp ≤ 0x2069 then some (.narrow .bidiIsolate)
  else if 0x200B ≤ cp ∧ cp ≤ 0x200F then some (.narrow .zeroWidth)
  else if cp = 0xFEFF then some (.narrow .bom)
  else if 0xE0000 ≤ cp ∧ cp ≤ 0xE007F then some (.narrow .tagCharacter)
  else if (0xFE00 ≤ cp ∧ cp ≤ 0xFE0F) ∨ (0xE0100 ≤ cp ∧ cp ≤ 0xE01EF)
    then some (.narrow .variationSelector)
  else if cp = 0xFFA0 ∨ cp = 0x3164 then some (.narrow .hangulFiller)
  else if cp = 0x00AD then some (.narrow .softHyphen)
  else if 0xFFF9 ≤ cp ∧ cp ≤ 0xFFFB then some (.narrow .interlinearAnnotation)
  else if cp = 0x180E then some (.narrow .mongolianVowelSeparator)
  else if isDefaultIgnorableCodepoint cp then some .defaultIgnorable
  else none

/-- Predicate form derived from `classifyCodepointIfForbidden`. -/
def isForbiddenCodepoint (cp : Nat) : Bool :=
  (classifyCodepointIfForbidden cp).isSome

theorem classify_U202E :
    classifyCodepointIfForbidden 0x202E = some (.narrow .bidiOverride) := by native_decide
theorem classify_U2067 :
    classifyCodepointIfForbidden 0x2067 = some (.narrow .bidiIsolate) := by native_decide
theorem classify_U200B :
    classifyCodepointIfForbidden 0x200B = some (.narrow .zeroWidth) := by native_decide
theorem classify_UFEFF :
    classifyCodepointIfForbidden 0xFEFF = some (.narrow .bom) := by native_decide
theorem classify_UE0041 :
    classifyCodepointIfForbidden 0xE0041 = some (.narrow .tagCharacter) := by native_decide
theorem classify_UFE00 :
    classifyCodepointIfForbidden 0xFE00 = some (.narrow .variationSelector) := by native_decide
theorem classify_U3164 :
    classifyCodepointIfForbidden 0x3164 = some (.narrow .hangulFiller) := by native_decide
theorem classify_U00AD :
    classifyCodepointIfForbidden 0x00AD = some (.narrow .softHyphen) := by native_decide
theorem classify_UFFF9 :
    classifyCodepointIfForbidden 0xFFF9 = some (.narrow .interlinearAnnotation) := by
  native_decide
theorem classify_U180E :
    classifyCodepointIfForbidden 0x180E = some (.narrow .mongolianVowelSeparator) := by
  native_decide

/-- COMBINING GRAPHEME JOINER U+034F is DICP but not in any narrow
    category — exercises the `defaultIgnorable` residual tier. -/
theorem classify_U034F_dicp :
    classifyCodepointIfForbidden 0x034F = some .defaultIgnorable := by native_decide

/-- WORD JOINER U+2060 is DICP but not in any narrow category. -/
theorem classify_U2060_dicp :
    classifyCodepointIfForbidden 0x2060 = some .defaultIgnorable := by native_decide

theorem classify_hello_letter_none :
    classifyCodepointIfForbidden 0x68 = none := by native_decide
theorem classify_digit_none :
    classifyCodepointIfForbidden 0x30 = none := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 CLASSIFIED-FORBIDDEN WALKER
-- Returns offset + codepoint + classification together so a strict
-- variant never needs a second-pass classification lookup.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- First forbidden codepoint in `bs`, bundled with its
    `ForbiddenClassification`. Returns `some (offset, cp, class)`
    at the first forbidden codepoint encountered, or `none` when
    the content has no forbidden codepoints. -/
def firstForbiddenCodepointClassified (bs : ByteArray) :
    Option (Nat × Nat × ForbiddenClassification) :=
  foldCodepointsWithOffset bs (Option.none : Option (Nat × Nat × ForbiddenClassification))
    (fun acc off cp =>
      match acc with
      | some r => some r
      | none   => match classifyCodepointIfForbidden cp with
                  | some kind => some (off, cp, kind)
                  | none      => none)

theorem firstForbidden_hello_none :
    firstForbiddenCodepointClassified "hello".toUTF8 = none := by native_decide

theorem firstForbidden_bidi :
    firstForbiddenCodepointClassified (ByteArray.mk #[0x61, 0xE2, 0x80, 0xAE, 0x62])
      = some (1, 0x202E, .narrow .bidiOverride) := by native_decide

theorem firstForbidden_bom :
    firstForbiddenCodepointClassified (ByteArray.mk #[0xEF, 0xBB, 0xBF])
      = some (0, 0xFEFF, .narrow .bom) := by native_decide

theorem firstForbidden_cgj :
    firstForbiddenCodepointClassified (ByteArray.mk #[0xCD, 0x8F])
      = some (0, 0x034F, .defaultIgnorable) := by native_decide

theorem firstForbidden_word_joiner :
    firstForbiddenCodepointClassified (ByteArray.mk #[0xE2, 0x81, 0xA0])
      = some (0, 0x2060, .defaultIgnorable) := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 AGGREGATE PRINTABLE PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The full printable-text predicate: four checks ANDed.

    Defined via the structural walkers' `.isNone` plus `isNFCBytes`
    rather than `bs.data.all`-style traversals, so any downstream
    offset-tracking variant remains by-definition consistent.

    The NFC stage runs last because only it depends on the holistic
    sequence rather than a per-byte or per-codepoint signal; the
    three earlier stages' cheaper rejections short-circuit its
    evaluation on invalid or forbidden inputs. -/
def isPrintableUtf8Bytes (bs : ByteArray) : Bool :=
  (firstInvalidUtf8Offset bs).isNone
    && (firstForbiddenControl bs).isNone
    && (firstForbiddenCodepointClassified bs).isNone
    && Utf8Bridge.isNFCBytes bs

theorem empty_is_printable :
    isPrintableUtf8Bytes ByteArray.empty = true := by native_decide
theorem hello_is_printable :
    isPrintableUtf8Bytes "hello".toUTF8 = true := by native_decide
theorem hello_nl_is_printable :
    isPrintableUtf8Bytes "hello\nworld".toUTF8 = true := by native_decide
theorem accented_is_printable :
    isPrintableUtf8Bytes "héllo".toUTF8 = true := by native_decide

theorem control_NUL_not_printable :
    isPrintableUtf8Bytes (ByteArray.mk #[0x00]) = false := by native_decide

theorem control_CR_not_printable :
    isPrintableUtf8Bytes (ByteArray.mk #[0x0D]) = false := by native_decide

theorem bidi_override_not_printable :
    isPrintableUtf8Bytes (ByteArray.mk #[0xE2, 0x80, 0xAE]) = false := by native_decide

theorem bom_not_printable :
    isPrintableUtf8Bytes (ByteArray.mk #[0xEF, 0xBB, 0xBF]) = false := by native_decide

theorem dicp_cgj_not_printable :
    isPrintableUtf8Bytes (ByteArray.mk #[0xCD, 0x8F]) = false := by native_decide

/-- Decomposed "e + combining acute" is valid UTF-8 with no forbidden
    codepoints, but it is not in NFC — the precomposed "é" is the NFC
    form. The aggregate predicate rejects. -/
theorem non_nfc_decomposed_e_not_printable :
    isPrintableUtf8Bytes (ByteArray.mk #[0x65, 0xCC, 0x81]) = false := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 REFINEMENT TYPE
-- ═══════════════════════════════════════════════════════════════════════════════

structure PrintableUtf8 (maxBytes : Nat) where
  bytes     : ByteArray
  sizeOk    : bytes.size ≤ maxBytes
  printable : isPrintableUtf8Bytes bytes = true

instance (maxBytes : Nat) : DecidableEq (PrintableUtf8 maxBytes) := fun a b =>
  if h : a.bytes = b.bytes then
    isTrue (by cases a; cases b; simp only [PrintableUtf8.mk.injEq]; exact h)
  else
    isFalse (fun heq => h (by rw [heq]))

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 CONSTRUCTION
-- ═══════════════════════════════════════════════════════════════════════════════

def PrintableUtf8.ofBytes? (maxBytes : Nat) (bs : ByteArray) :
    Option (PrintableUtf8 maxBytes) :=
  if hSize : bs.size ≤ maxBytes then
    if hPrint : isPrintableUtf8Bytes bs = true then
      some ⟨bs, hSize, hPrint⟩
    else none
  else none

theorem PrintableUtf8.ofBytes?_self {maxBytes : Nat} (r : PrintableUtf8 maxBytes) :
    PrintableUtf8.ofBytes? maxBytes r.bytes = some r := by
  cases r with
  | mk bytes sizeOk printable =>
    unfold ofBytes?
    simp [sizeOk, printable]

end Unicode.Codec.Printable
