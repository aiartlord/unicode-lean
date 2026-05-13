/-
  Unicode.UCD

  Programmatic interface to the SHA-256 digests of bundled UCD
  source files. Exposes the same data that
  `scripts/check-ucd-hashes.sh` checks at the shell level so
  downstream tools can run verification or auditing in pure Lean
  rather than via shell-out.

  Three values:

    * `currentUcdVersion`  — the UCD release this distribution was
                              built from (`17.0.0`). Per-file UCA
                              data tracks UCA 16.0.0 because the
                              UCA always lags one UCD release; those
                              files are marked in their filenames
                              (e.g. `PropListUca16.txt`).
    * `ucdFileDigests`     — every (filename, expected SHA-256)
                              pair parsed from the `SHA256SUMS`
                              manifest at compile time.
    * `expectedUcdFiles`   — just the filenames, preserving the
                              order they appear in the manifest.

  All three are pure values — `include_str` embeds the manifest
  bytes at build time, the inline parser runs once at module load.
-/

namespace Unicode.UCD

/-- The UCD release pinned by this distribution. -/
def currentUcdVersion : String := "17.0.0"

/-- Raw text of `SHA256SUMS`, embedded at compile time. -/
private def sha256sumsRaw : String := include_str "Ucd/SHA256SUMS"

@[inline]
private def trimS (s : String) : String := (String.trimAscii s).toString

/-- Parse one line of `sha256sum`-format output: 64 hex digits, two
    spaces, filename. Returns `none` on malformed or blank lines. -/
private def parseSha256Line (line : String) : Option (String × String) :=
  let trimmed := trimS line
  if trimmed.isEmpty then none
  else
    match trimmed.splitOn "  " with
    | [hash, filename] =>
      let h := trimS hash
      let f := trimS filename
      if h.length = 64 ∧ ¬ f.isEmpty then
        some (f, h)
      else
        Function.const String none f
    | malformed => Function.const (List String) none malformed

/-- All `(filename, expected SHA-256)` pairs, in manifest order. -/
def ucdFileDigests : List (String × String) :=
  (sha256sumsRaw.splitOn "\n").filterMap parseSha256Line

/-- Filenames of every UCD source file pinned in this distribution. -/
def expectedUcdFiles : List String :=
  ucdFileDigests.map (·.fst)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SHAPE CHECKS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The trusted base pins 48 UCD source files — one entry per
    vendored file under `Unicode/Ucd/`, each carrying the
    SHA-256 of its bytes as written at release time.

    The cardinality is itself proof-relevant: it forces every
    addition or removal in `Ucd/SHA256SUMS` through this
    constant, so the trusted base cannot grow or shrink without
    a visible diff.  Equivalent to a length-indexed manifest. -/
theorem ucdFileDigests_count : ucdFileDigests.length = 48 := by native_decide

/-- Every digest entry has the expected 64-hex-character SHA-256
    payload. -/
theorem ucdFileDigests_all_64 :
    ucdFileDigests.all (fun fh => fh.snd.length = 64) = true := by native_decide

/-- Sanity check on a representative entry (the canonical
    `UnicodeData.txt`). -/
theorem ucdFileDigests_unicode_data :
    ucdFileDigests.find? (fun fh => fh.fst = "UnicodeData.txt")
      = some ("UnicodeData.txt",
              "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c") := by
  native_decide

end Unicode.UCD
