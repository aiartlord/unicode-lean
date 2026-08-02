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

end Unicode.Conformance.Security.Bip39CanonicalTest
