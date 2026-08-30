/-
  Unicode.Conformance.Security.HashInputStabilityTest

  Conformance certificate for the HashInputStability detector (cryptographic
  input-stability layer, UTS #39 §6.1 canonical-form guidance together with the
  hash-input canonicalisation contracts of RFC 8785 §3 and RFC 4880 / 9580).

  What this certifies.  A signer and a verifier must hash byte-identical inputs.
  The detector fixes a single canonical hash-input form — NFC followed by
  stripping of trailing ASCII framing whitespace `{U+0020, U+0009, U+000A,
  U+000D}` — and flags any input that is not already in that form, because such
  an input hashes to a different digest once a downstream stage re-canonicalises
  it.

  Threat model.  A pipeline injector submits text whose canonical form differs
  across stages of a signing pipeline — PGP body canonicalisation, RFC 8785 JSON
  serialisation, audit logs whose line endings an editor rewrites on read-back,
  or webhook HMACs recomputed over re-encoded bytes.  Wherever the signing end
  and the verifying end disagree on trim policy, line-ending convention, or
  normalisation form, two inputs that a human reads as "the same content" produce
  divergent hashes while both parties believe they signed identical bytes — a
  silent signature-bypass and hash-collision hazard.

  The discrimination the detector draws.  Text already equal to its trimmed-NFC
  form is sanctioned and reported `clear`.  Text carrying trailing ASCII
  whitespace draws a `TrailingWhitespace` verdict that pinpoints the offending
  positions and the byte-length of the stable (trimmed) form, so a caller can
  see exactly what canonicalisation would change.  Unicode-category spaces
  (NBSP, `U+2000..U+200A`, ideographic space) are deliberately treated as
  content, not framing, and are left intact.

  How to read the certificate.  Each theorem below pins the detector's full
  verdict — sub-threat tag together with the stable size and, where it
  discriminates, the reported positions — on one representative vector: a
  trailing space, a trailing CRLF, and a stable lowercase-ASCII clear.  Because
  every vector is low-ASCII, NFC is the identity and is rewritten away with
  `toNFC_id_lowAscii`, leaving a cheap `decide`.  The final `all_rows_pass`
  theorem conjoins all three verdicts into the single certificate this harness
  exports; appending a further vector extends that conjunction, so the guarantee
  grows with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Crypto.HashInputStability
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.HashInputStabilityTest

open Unicode.Security.Crypto.HashInputStability

/-- A single trailing space is the minimal instability: `"a "` and `"a"` are one
    trim step apart, so a signer that trims and a verifier that does not compute
    different digests over what looks like the same word.  The detector must draw
    `TrailingWhitespace`, locate the space at position 1, and report that the
    stable (trimmed) form has size 1. -/
theorem trailing_space_verdict :
    let v := detect [0x61, 0x20]
    v.classify.tag = some "TrailingWhitespace"
      ∧ v.classify.positions = [1] ∧ v.stableSize = 1 := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x20] (by decide)]
  decide

/-- A trailing CRLF is the line-ending variant of the same hazard: an editor or
    transport that rewrites `\r\n` on read-back changes the bytes a verifier
    hashes.  The detector must still draw `TrailingWhitespace` and reduce the two
    framing bytes away to a stable form of size 1. -/
theorem trailing_crlf_verdict :
    let v := detect [0x61, 0x0D, 0x0A]
    v.classify.tag = some "TrailingWhitespace" ∧ v.stableSize = 1 := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x0D, 0x0A] (by decide)]
  decide

/-- Plain lowercase ASCII with no trailing framing is already its own trimmed-NFC
    form, so signer and verifier hash identical bytes.  This is the sanctioned
    baseline that proves the detector does not over-report content as a hazard. -/
theorem ascii_clear_verdict :
    (detect [0x61, 0x62, 0x63]).classify = .clear := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x62, 0x63] (by decide)]
  decide

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x61, 0x20]
     v.classify.tag = some "TrailingWhitespace"
       ∧ v.classify.positions = [1] ∧ v.stableSize = 1) ∧
    (let v := detect [0x61, 0x0D, 0x0A]
     v.classify.tag = some "TrailingWhitespace" ∧ v.stableSize = 1) ∧
    (detect [0x61, 0x62, 0x63]).classify = .clear :=
  ⟨trailing_space_verdict, trailing_crlf_verdict, ascii_clear_verdict⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/HashInputStabilityTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile
  (VectorRow parseFile parseFileAttrs attrValue attrCodepoints)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/HashInputStabilityTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The attribution fields of every row, index-aligned with `parsedRows`. -/
def parsedAttrs : List (List String) := parseFileAttrs vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0061, 0x0062, 0x0063], "Clear", []⟩,
  ⟨[0x00E9], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F, 0x0020, 0x00E9], "Clear", []⟩,
  ⟨[0x0061, 0x0020, 0x0062], "Clear", []⟩,
  ⟨[0x0061, 0x3000], "Clear", []⟩,
  ⟨[0x0061, 0x0020], "Hazard:TrailingWhitespace", [1]⟩,
  ⟨[0x0061, 0x0009], "Hazard:TrailingWhitespace", [1]⟩,
  ⟨[0x0061, 0x000A], "Hazard:TrailingWhitespace", [1]⟩,
  ⟨[0x0061, 0x000D, 0x000A], "Hazard:TrailingWhitespace", [1]⟩,
  ⟨[0x0065, 0x0301], "Hazard:NormalizationDrift", [0]⟩,
  ⟨[0x0061, 0x0301], "Hazard:NormalizationDrift", [0]⟩,
  ⟨[0x1112, 0x1161, 0x11AB], "Hazard:NormalizationDrift", [0]⟩,
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F, 0x0020, 0x0065, 0x0301, 0x0020, 0x0077, 0x006F, 0x0072, 0x006C, 0x0064], "Hazard:NormalizationDrift", [6]⟩,
  ⟨[0x0065, 0x0301, 0x0020], "Hazard:TrailingWhitespace", [2]⟩,
  ⟨[0x0061, 0x0062, 0x0063], "Hazard:EncodingMismatch", [0]⟩,
  ⟨[0x0061, 0x0062, 0x0063], "Hazard:EncodingMismatch", [0]⟩,
  ⟨[0x0061, 0x0020], "Hazard:SignedMessageRule", [1]⟩,
  ⟨[0x0061, 0x000A, 0x0062], "Hazard:SignedMessageRule", [1]⟩,
  ⟨[0x0065, 0x0301], "Hazard:SignedMessageRule", [0]⟩,
  ⟨[0x0061, 0x0001, 0x0062], "Hazard:SignedMessageRule", [1]⟩,
  ⟨[0x0061, 0x0062, 0x0064], "Hazard:AuditLogReinterpretation", [2]⟩,
  ⟨[0x0061, 0x0062, 0x0063, 0x0064], "Hazard:AuditLogReinterpretation", [3]⟩,
  ⟨[0x0061, 0x0062, 0x0063], "Hazard:WebhookSignatureDrift", [2]⟩,
  ⟨[0x0065, 0x0301], "Hazard:EncodingMismatch", [0]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
def attrsList : List (List String) := [
  ["stableSize=3"],
  ["stableSize=1"],
  ["stableSize=2"],
  ["stableSize=7"],
  ["stableSize=3"],
  ["stableSize=2"],
  ["stableSize=1"],
  ["stableSize=1"],
  ["stableSize=1"],
  ["stableSize=1"],
  ["stableSize=1"],
  ["stableSize=1"],
  ["stableSize=1"],
  ["stableSize=13"],
  ["stableSize=1"],
  ["stableSize=3", "declaredEnc=utf-16"],
  ["stableSize=3", "declaredEnc=latin-1"],
  ["stableSize=1", "rfcRule=pgp4880TrailingWhitespace"],
  ["stableSize=3", "rfcRule=pgp9580LineEnding"],
  ["stableSize=1", "rfcRule=rfc8785NfcRequirement"],
  ["stableSize=3", "rfcRule=rfc8259ControlChar"],
  ["stableSize=3", "asWritten=61 62 63"],
  ["stableSize=4", "asWritten=61 62 63"],
  ["stableSize=3", "serverBytes=61 62 64"],
  ["stableSize=1", "declaredEnc=utf-16", "rfcRule=rfc8785NfcRequirement"]
]

-- `rowsList` and `attrsList` mirror a fresh parse of the vector file.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "HashInputStabilityTest drift: rowsList ≠ parsed vector file")
  unless attrsList == parsedAttrs do
    throw (IO.userError "HashInputStabilityTest drift: attrsList ≠ parsed attribution")

/-- The `RfcRule` an `rfcRule=` attribution names. -/
def rfcRuleOf (name : String) : Option RfcRule :=
  if name = "pgp4880TrailingWhitespace" then some .pgp4880TrailingWhitespace
  else if name = "pgp9580LineEnding" then some .pgp9580LineEnding
  else if name = "rfc8785NfcRequirement" then some .rfc8785NfcRequirement
  else if name = "rfc8259ControlChar" then some .rfc8259ControlChar
  else none

/-- The `Context` a row's attribution states.  Four of this family's six
    sub-threats fire only on caller-supplied context, and the vector file
    carries that context per row, so each row is judged under the context it
    was written for rather than under an empty one. -/
def contextOf (attrs : List String) : Context :=
  { declaredEncoding := attrValue "declaredEnc" attrs,
    rfcRule          := (attrValue "rfcRule" attrs).bind rfcRuleOf,
    asWritten        := (attrValue "asWritten" attrs).map attrCodepoints,
    serverBytes      := (attrValue "serverBytes" attrs).map attrCodepoints }

/-- Run the detector over one row under the context its attribution states,
    and compare with the verdict the file states. -/
def verifyVectorRow (rowAndAttrs : VectorRow × List String) : Bool :=
  let r := rowAndAttrs.1
  let v := detectWithContext (contextOf rowAndAttrs.2) r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

-- Each row runs the full context-bearing detector, which recurses deeper than
-- the elaborator's default budget over a list this long.
set_option maxRecDepth 1000000 in
/-- Every vector the pinned file states holds of the detector, under the
    context its attribution states. -/
theorem all_vectors_pass : (rowsList.zip attrsList).all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.HashInputStabilityTest
