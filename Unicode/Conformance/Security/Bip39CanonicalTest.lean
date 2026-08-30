/-
  Unicode.Conformance.Security.Bip39CanonicalTest

  Conformance certificate for the Bip39Canonical detector (cryptographic layer:
  BIP-39 recovery mnemonics that are not in canonical form).

  Threat model.  A wallet derives its seed by running the typed mnemonic through
  BIP-39's canonicalisation — NFKD, lowercasing, whitespace collapse, and
  trimming — before feeding it to the PBKDF2-HMAC-SHA512 key-derivation pipeline.
  When the bytes a user actually types differ from that canonical form, the
  derived seed silently diverges: recovery either fails outright or unlocks a
  different, empty wallet.  An adversary who can nudge a mnemonic toward a
  visually identical but non-canonical spelling — a capitalised word, an extra
  space, a compatibility ligature that NFKD would decompose — can make funds
  irrecoverable without ever touching the ciphertext.

  What the detector draws.  It reproduces the BIP-39 canonical form and compares
  it against the raw input, reporting the highest-priority anomaly it finds:
  `MixedCase` for uppercase ASCII that lowercasing would erase,
  `WhitespaceAnomaly` for a leading or doubled whitespace run, `NonNFKD` for a
  character whose NFKD expansion differs, and so on down the sub-threat order.
  A mnemonic whose canonical form matches the input, all of whose words belong to
  a single wordlist, passes as clear and names that language.

  How to read the certificate.  Each `Row` pairs an `input` with the
  classification `tag` its verdict must carry, where `none` denotes a clear
  verdict (a clear classification reports no tag, so a single `Option String`
  captures both hazardous and sanctioned outcomes).  `verifyRow` recomputes
  `detect` and compares its tag against the row; `all_rows_pass` discharges the
  whole table in the kernel.  Appending a vector adds a conjunct to that proof
  obligation, so the certificate grows with the threat catalogue and coverage
  cannot silently regress.
-/

import Unicode.Security.Crypto.Bip39Canonical
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.Bip39CanonicalTest

open Unicode.Security.Crypto.Bip39Canonical

set_option maxRecDepth 1000000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` codepoint sequence and the classification
    `tag` its verdict must carry (`none` for a clear verdict). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- "Abandon": the leading capital is the discriminating mistake — lowercasing
    -- would erase it, so the typed bytes derive a different seed than the word.
    { input := [0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E], tag := some "MixedCase" },
    -- A single leading space before "abandon": trimming removes it, so the
    -- pre-canonical run is exactly the whitespace anomaly the detector must flag.
    { input := [0x20, 0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E], tag := some "WhitespaceAnomaly" },
    -- The `ﬀ` ligature (U+FB00): a single character whose NFKD expands to "ff",
    -- the discriminating case for a non-NFKD form that canonicalisation rewrites.
    { input := [0xFB00], tag := some "NonNFKD" },
    -- Empty input: nothing to canonicalise and no anomaly can fire, so the
    -- verdict is clear — the boundary case that must not read as a hazard.
    { input := [], tag := none } ]

/-- A row passes when `detect` reproduces exactly the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the canonicalisation verdict the BIP-39
    pipeline demands. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/Bip39CanonicalTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/Bip39CanonicalTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x006F, 0x0075, 0x0074], "Clear", []⟩,
  ⟨[0x0061, 0x0301, 0x0062, 0x0061, 0x0063, 0x006F, 0x0020, 0x0061, 0x0062, 0x0064, 0x006F, 0x006D, 0x0065, 0x006E, 0x0020, 0x0061, 0x0062, 0x0065, 0x006A, 0x0061], "Clear", []⟩,
  ⟨[0x0061, 0x0062, 0x0061, 0x0063, 0x006F, 0x0020, 0x0061, 0x0062, 0x0062, 0x0061, 0x0067, 0x006C, 0x0069, 0x006F, 0x0020, 0x0061, 0x0062, 0x0062, 0x0069, 0x006E, 0x0061, 0x0074, 0x006F], "Clear", []⟩,
  ⟨[0x0061, 0x0062, 0x0061, 0x0069, 0x0073, 0x0073, 0x0065, 0x0072, 0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0061, 0x0062, 0x0064, 0x0069, 0x0071, 0x0075, 0x0065, 0x0072], "Clear", []⟩,
  ⟨[0x0061, 0x0062, 0x0064, 0x0069, 0x006B, 0x0061, 0x0063, 0x0065, 0x0020, 0x0061, 0x0062, 0x0065, 0x0063, 0x0065, 0x0064, 0x0061, 0x0020, 0x0061, 0x0064, 0x0072, 0x0065, 0x0073, 0x0061], "Clear", []⟩,
  ⟨[0x0061, 0x0062, 0x0061, 0x0063, 0x0061, 0x0074, 0x0065, 0x0020, 0x0061, 0x0062, 0x0061, 0x0069, 0x0078, 0x006F, 0x0020, 0x0061, 0x0062, 0x0061, 0x006C, 0x0061, 0x0072], "Clear", []⟩,
  ⟨[0x3042, 0x3044, 0x3053, 0x304F, 0x3057, 0x3093, 0x0020, 0x3042, 0x3044, 0x3055, 0x3064, 0x0020, 0x3042, 0x3044, 0x305F, 0x3099], "Clear", []⟩,
  ⟨[0x00E1, 0x0062, 0x0061, 0x0063, 0x006F], "Hazard:NonNFKD", [0]⟩,
  ⟨[0xFB01], "Hazard:NonNFKD", [0]⟩,
  ⟨[0x0061, 0x00A0, 0x0062], "Hazard:NonNFKD", [1]⟩,
  ⟨[0x3042, 0x3044, 0x3053, 0x304F, 0x3057, 0x3093, 0x3000, 0x3042, 0x3044, 0x3055, 0x3064, 0x3000, 0x3042, 0x3044, 0x3060], "Hazard:NonNFKD", [6]⟩,
  ⟨[0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020], "Hazard:TrailingWhitespace", [7]⟩,
  ⟨[0x3042, 0x3044, 0x3053, 0x304F, 0x3057, 0x3093, 0x3000], "Hazard:TrailingWhitespace", [6]⟩,
  ⟨[0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0020, 0x0061, 0x0062, 0x006F, 0x0075, 0x0074], "Hazard:WhitespaceAnomaly", [7]⟩,
  ⟨[0x0020, 0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E], "Hazard:WhitespaceAnomaly", [0]⟩,
  ⟨[0x0041, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E], "Hazard:MixedCase", [0]⟩,
  ⟨[0x0041, 0x0042, 0x0041, 0x004E, 0x0044, 0x004F, 0x004E], "Hazard:MixedCase", [0]⟩,
  ⟨[0x0071, 0x007A, 0x0071, 0x007A], "Hazard:WordlistMismatch", [0]⟩,
  ⟨[0x0061, 0x0062, 0x0061, 0x006E, 0x0064, 0x006F, 0x006E, 0x0020, 0x0071, 0x007A, 0x0071, 0x007A], "Hazard:WordlistMismatch", [1]⟩,
  ⟨[0x0061, 0x0301, 0x0062, 0x0061, 0x0063, 0x006F, 0x0020, 0x0061, 0x0062, 0x0061, 0x0063, 0x006F], "Hazard:LanguageAmbiguous", []⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "Bip39CanonicalTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.Bip39CanonicalTest
