/-
  Unicode.Normalization.Utf8Bridge

  UTF-8 ↔ codepoint bridge for the byte-level NFC wrappers.

  The codepoint-level algorithms in `Normalization/{Decompose,Reorder,
  Compose,NFC}.lean` operate on `List Nat`. Downstream consumers work
  with `List UInt8`. This module bridges the two by providing:

    * `decodeToCodepoints`  List UInt8 → List Nat
                            (via `Unicode.Codec.Utf8`'s strict fold;
                             yields the longest valid prefix if the
                             input isn't fully valid — callers are
                             expected to validate first).
    * `encodeCodepoint`     Nat → List UInt8
                            (1-4 bytes per UAX #44 §5.1).
    * `encodeCodepoints`    List Nat → List UInt8
    * `toNFCBytes`          List UInt8 → Option List UInt8
                            (Some when input is valid UTF-8; None
                             otherwise.)
    * `isNFCBytes`          List UInt8 → Bool
                            (true iff `toNFCBytes bs = some bs`.)
-/

import Unicode.Codec.Utf8
import Unicode.Normalization.NFC

namespace Unicode.Normalization.Utf8Bridge

open Unicode.Codec.Utf8 (foldCodepointsWithOffset isValidUtf8)
open Unicode.Normalization

set_option maxRecDepth 100000

/-- Decode a UTF-8 byte array to a codepoint array. Semantically
    meaningful only when `isValidUtf8 bs = true`; on malformed input
    the fold yields the longest valid prefix and stops. Callers that
    need failure propagation use `toNFCBytes` which validates up front. -/
def decodeToCodepoints (bs : List UInt8) : List Nat :=
  foldCodepointsWithOffset bs ([] : List Nat)
    (fun acc offset cp => Function.const Nat (acc ++ [cp]) offset)

/-- Encode a single codepoint as 1-4 UTF-8 bytes per UAX #44 §5.1.
    Assumes `cp < 0x110000` — invalid codepoints above that range
    produce bogus output; the calling pipeline never surfaces them
    because `Unicode.Codec.Utf8.utf8DecodeStep` rejects them during
    decoding. -/
def encodeCodepoint (cp : Nat) : List UInt8 :=
  if cp < 0x80 then
    [UInt8.ofNat cp]
  else if cp < 0x800 then
    [
      UInt8.ofNat (0xC0 ||| (cp >>> 6)),
      UInt8.ofNat (0x80 ||| (cp &&& 0x3F))
    ]
  else if cp < 0x10000 then
    [
      UInt8.ofNat (0xE0 ||| (cp >>> 12)),
      UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
      UInt8.ofNat (0x80 ||| (cp &&& 0x3F))
    ]
  else
    [
      UInt8.ofNat (0xF0 ||| (cp >>> 18)),
      UInt8.ofNat (0x80 ||| ((cp >>> 12) &&& 0x3F)),
      UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
      UInt8.ofNat (0x80 ||| (cp &&& 0x3F))
    ]

/-- Concatenate the UTF-8 encodings of a codepoint sequence. -/
def encodeCodepoints (cps : List Nat) : List UInt8 :=
  cps.foldl (fun acc cp => acc ++ encodeCodepoint cp) ([] : List UInt8)

/-- Byte-level NFC: validate UTF-8, decode, normalize, re-encode.
    Returns `none` on invalid UTF-8 input; the NFC algorithm itself
    does not fail on any valid UTF-8 sequence. -/
def toNFCBytes (bs : List UInt8) : Option List UInt8 :=
  if isValidUtf8 bs then
    some (encodeCodepoints (NFC.toNFC (decodeToCodepoints bs)))
  else
    none

/-- Byte-level NFC check: `true` iff `bs` is valid UTF-8 AND running
    the NFC pipeline leaves it unchanged. Returns `false` for invalid
    UTF-8 (since such input has no defined NFC form at the byte level). -/
def isNFCBytes (bs : List UInt8) : Bool :=
  match toNFCBytes bs with
  | some out => decide (out = bs)
  | none     => false

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
-- Codec-only vectors close by decide — encode/decode is pure arithmetic.
-- Pipeline vectors rewrite the normalization stage through the NFC value
-- lemmas first, so the row tables are never reduced; the codec residue
-- then closes by decide.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Single-byte ASCII encodes to one byte. -/
theorem encode_A : encodeCodepoint 0x0041 = [0x41] := by decide

/-- LATIN CAPITAL LETTER A WITH GRAVE (`À`, U+00C0) encodes to two bytes:
    0xC3 0x80. -/
theorem encode_A_grave :
    encodeCodepoint 0x00C0 = [0xC3, 0x80] := by decide

/-- `é` (U+00E9) encodes to 0xC3 0xA9. -/
theorem encode_eacute :
    encodeCodepoint 0x00E9 = [0xC3, 0xA9] := by decide

/-- HIRAGANA LETTER A (`あ`, U+3042) encodes to three bytes:
    0xE3 0x81 0x82. -/
theorem encode_hiragana_a :
    encodeCodepoint 0x3042 = [0xE3, 0x81, 0x82] := by decide

/-- GRINNING FACE (`😀`, U+1F600) encodes to four bytes:
    0xF0 0x9F 0x98 0x80. -/
theorem encode_emoji :
    encodeCodepoint 0x1F600 = [0xF0, 0x9F, 0x98, 0x80] := by decide

/-- Decoding "Hi" (pure ASCII) yields the codepoint array. -/
theorem decode_ascii :
    decodeToCodepoints ([0x48, 0x69]) = [0x48, 0x69] := by decide

/-- Decoding the UTF-8 bytes of `À` yields `[0x00C0]`. -/
theorem decode_A_grave :
    decodeToCodepoints ([0xC3, 0x80]) = [0x00C0] := by decide

/-- Encode-then-decode round-trip for a single `A`. -/
theorem roundtrip_A :
    decodeToCodepoints (encodeCodepoint 0x0041) = [0x0041] := by decide

/-- Encode-then-decode round-trip for HIRAGANA A. -/
theorem roundtrip_hiragana_a :
    decodeToCodepoints (encodeCodepoint 0x3042) = [0x3042] := by decide

/-- NFC on the ASCII bytes of "Hi" is a no-op. -/
theorem toNFCBytes_ascii :
    toNFCBytes ([0x48, 0x69]) = some ([0x48, 0x69]) := by
  rewrite [toNFCBytes.eq_def,
    show decodeToCodepoints ([0x48, 0x69]) = [0x0048, 0x0069]
      from by decide,
    NFC.toNFC_ascii]
  decide

theorem isNFCBytes_ascii :
    isNFCBytes ([0x48, 0x69]) = true := by
  rewrite [isNFCBytes.eq_def, toNFCBytes_ascii]
  decide

/-- Decomposed `A` + combining grave (0x41, 0xCC, 0x80) normalizes to
    precomposed `À` (0xC3, 0x80). -/
theorem toNFCBytes_composes :
    toNFCBytes ([0x41, 0xCC, 0x80])
      = some ([0xC3, 0x80]) := by
  rewrite [toNFCBytes.eq_def,
    show decodeToCodepoints ([0x41, 0xCC, 0x80])
        = [0x0041, 0x0300] from by decide,
    NFC.toNFC_composes_A_grave]
  decide

/-- Precomposed `À` (0xC3, 0x80) is already in NFC. -/
theorem isNFCBytes_A_grave :
    isNFCBytes ([0xC3, 0x80]) = true := by
  rewrite [isNFCBytes.eq_def, toNFCBytes.eq_def,
    show decodeToCodepoints ([0xC3, 0x80]) = [0x00C0]
      from by decide,
    NFC.toNFC_idempotent_on_A_grave]
  decide

/-- Decomposed form is NOT in NFC at the byte level. -/
theorem isNFCBytes_decomposed :
    isNFCBytes ([0x41, 0xCC, 0x80]) = false := by
  rewrite [isNFCBytes.eq_def, toNFCBytes_composes]
  decide

/-- Invalid UTF-8 (lone continuation byte) returns none. -/
theorem toNFCBytes_invalid :
    toNFCBytes ([0x80]) = none := by decide

theorem isNFCBytes_invalid :
    isNFCBytes ([0x80]) = false := by decide

end Unicode.Normalization.Utf8Bridge
