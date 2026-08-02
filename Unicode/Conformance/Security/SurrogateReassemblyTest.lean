/-
  Unicode.Conformance.Security.SurrogateReassemblyTest

  What this harness certifies.  It pins the verdicts of the SurrogateReassembly
  detector, which decides whether a raw byte stream is well-formed UTF-8 in the
  sense of the Unicode Standard §3.9, definition D92 and Table 3-7 (Well-Formed
  UTF-8 Byte Sequences).  Table 3-7 fixes the exact ranges each continuation byte
  may take, which is precisely what rules out overlong encodings and the
  surrogate code points U+D800..U+DFFF; the surrogate case doubles as a CESU-8
  detector, CESU-8 being the compatibility encoding standardised in UTS #26 that
  encodes supplementary characters as a surrogate pair rather than a single
  four-byte sequence.

  Threat model.  A decoder that silently repairs malformed UTF-8 lets an attacker
  smuggle a code point past a filter in a form the filter did not recognise:
  '/' hidden as a three-byte overlong sequence slips through a path check, and a
  supplementary character split into surrogate halves (CESU-8) reassembles only
  after the security boundary has waved it through.  Truncated and invalid-start
  bytes are the corruption cases that a lenient decoder would otherwise paper over
  with U+FFFD, discarding the evidence that the input was ill-formed.

  The discrimination the detector draws.  A byte stream that conforms to Table 3-7
  is reported clear with no invalid offset; any stream that departs from it is
  classified by its specific defect — `Overlong`, `Cesu8`, `Truncated`, or
  `InvalidStartByte` — and carries the byte count and the offset of the first
  byte at which conformance fails, so the verdict names both the fault and where
  it occurs.

  How to read the certificate.  Each theorem below fixes the complete verdict —
  sub-threat tag together with byte count and first-invalid offset — on one
  discriminating byte stream: a three-byte overlong solidus, a CESU-8 surrogate
  half, a truncated four-byte sequence, a byte that can never begin a UTF-8
  sequence, and a well-formed four-byte emoji as the negative control.
  `all_rows_pass` conjoins every one of those verdicts into a single closed
  theorem; appending a new vector extends that conjunction, so the harness's total
  obligation grows with the threat catalogue and no covered case can silently
  regress.
-/

import Unicode.Security.Covert.SurrogateReassembly

namespace Unicode.Conformance.Security.SurrogateReassemblyTest

open Unicode.Security.Covert.SurrogateReassembly

/-- The bytes 0xE0 0x80 0xAF spell U+002F SOLIDUS as a three-byte sequence, but
    '/' fits in one byte, so Table 3-7 forbids the second byte falling below 0xA0
    after a 0xE0 lead: this is the overlong-encoding attack that hides a path
    separator from a naive filter, and the detector must flag it as `Overlong`
    from offset 0. -/
theorem overlong_verdict :
    let v := detect [0xE0, 0x80, 0xAF]
    v.classify.tag = some "Overlong"
      ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 0 := by decide

/-- The bytes 0xED 0xA0 0x80 encode the isolated surrogate U+D800, which Table 3-7
    excludes by capping the byte after a 0xED lead at 0x9F: the detector recognises
    this as the CESU-8 signature — a surrogate half that would reassemble into a
    supplementary character only after passing a security boundary — and confirms
    it as `Cesu8` once the third byte (offset 2) completes the surrogate. -/
theorem cesu8_verdict :
    let v := detect [0xED, 0xA0, 0x80]
    v.classify.tag = some "Cesu8"
      ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 2 := by decide

/-- A 0xF0 lead byte announces a four-byte sequence, but only two continuation
    bytes follow (0x9F 0x98), so the stream ends one byte short: the detector must
    not repair the gap with U+FFFD but report the incomplete sequence as
    `Truncated`, pointing at offset 3 where the missing fourth byte was due. -/
theorem truncated_verdict :
    let v := detect [0xF0, 0x9F, 0x98]
    v.classify.tag = some "Truncated"
      ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 3 := by decide

/-- The byte 0xFE lies outside every lead-byte range of Table 3-7 and can never
    legally begin — or appear anywhere in — a UTF-8 sequence, so the detector
    rejects it outright as an `InvalidStartByte` at offset 0 rather than treating
    it as the start of some multi-byte form. -/
theorem invalid_start_verdict :
    let v := detect [0xFE]
    v.classify.tag = some "InvalidStartByte"
      ∧ v.byteCount = 1 ∧ v.firstInvalidOffset = some 0 := by decide

/-- The bytes 0xF0 0x9F 0x98 0x80 are the well-formed four-byte encoding of
    U+1F600 GRINNING FACE, every byte inside its Table 3-7 range: this is the
    negative control that proves the detector passes conforming input clear with
    no invalid offset, so the hazard verdicts above are discriminating rather than
    a blanket rejection of long sequences. -/
theorem valid_emoji_clear_verdict :
    let v := detect [0xF0, 0x9F, 0x98, 0x80]
    v.classify.isClear = true
      ∧ v.byteCount = 4 ∧ v.firstInvalidOffset = none := by decide

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0xE0, 0x80, 0xAF];
      v.classify.tag = some "Overlong"
        ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 0) ∧
    (let v := detect [0xED, 0xA0, 0x80];
      v.classify.tag = some "Cesu8"
        ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 2) ∧
    (let v := detect [0xF0, 0x9F, 0x98];
      v.classify.tag = some "Truncated"
        ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 3) ∧
    (let v := detect [0xFE];
      v.classify.tag = some "InvalidStartByte"
        ∧ v.byteCount = 1 ∧ v.firstInvalidOffset = some 0) ∧
    (let v := detect [0xF0, 0x9F, 0x98, 0x80];
      v.classify.isClear = true
        ∧ v.byteCount = 4 ∧ v.firstInvalidOffset = none) :=
  ⟨overlong_verdict, cesu8_verdict, truncated_verdict,
    invalid_start_verdict, valid_emoji_clear_verdict⟩

end Unicode.Conformance.Security.SurrogateReassemblyTest
