/-
  scripts/gen-security-fixtures.lean

  Generate the shared cross-port detector contract fixtures from the Lean detectors
  themselves — the single source of truth. For each curated vector input, run the
  product's own `Unicode.Security.Policy.scan` and emit the reason codes it produces
  (`Finding.code`) as the fixture's `required_findings`. This makes the shared contract
  provably the Lean behaviour rather than hand-authored JSON, so every port validated
  against it is genuinely backed by Lean.

  Run:  lake env lean scripts/gen-security-fixtures.lean         (prints JSON to stdout)
  Fixtures are test data derived from the proven detectors; this uses runtime scan, not
  the kernel-proof moat.
-/

import Unicode.Security.Policy

open Unicode.Security.Policy

/-- One curated contract case: a name and the codepoint input. -/
structure GenCase where
  name  : String
  input : List Nat

/-- One family's contract: its slug and curated cases. -/
structure GenFamily where
  slug  : String
  cases : List GenCase

-- ── minimal JSON emit (fixture schema: {schema, family, cases:[{name,input,required_findings}]}) ──

private def jNatList (xs : List Nat) : String :=
  "[" ++ String.intercalate ", " (xs.map toString) ++ "]"

private def jStrList (xs : List String) : String :=
  "[" ++ String.intercalate ", " (xs.map (fun s => "\"" ++ s ++ "\"")) ++ "]"

/-- Reason codes the Lean detectors actually emit for `input`, restricted to the
    named family (the shared contract's per-family `required_findings` are a subset:
    what MUST fire for this family, since `scan` runs every detector). Ground truth
    straight from the product's own `scan`. -/
private def containsInfix (s sub : String) : Bool := (s.splitOn sub).length > 1

def findingsFor (slug : String) (input : List Nat) : List String :=
  let famInfix := "." ++ slug ++ "."
  (((scan Profile.chatMessage Mode.observe input).findings.map (·.code)).filter
    (fun code => containsInfix code famInfix)).eraseDups

def emitCase (slug : String) (c : GenCase) : String :=
  let codes := findingsFor slug c.input
  "    {\n" ++
  s!"      \"name\": \"{c.name}\",\n" ++
  s!"      \"input\": {jNatList c.input},\n" ++
  s!"      \"required_findings\": {jStrList codes}\n" ++
  "    }"

def emitFamily (f : GenFamily) : String :=
  "{\n" ++
  "  \"schema\": 1,\n" ++
  s!"  \"family\": \"{f.slug}\",\n" ++
  "  \"cases\": [\n" ++
  String.intercalate ",\n" (f.cases.map (emitCase f.slug)) ++ "\n" ++
  "  ]\n" ++
  "}"

-- ── seed vectors (validation set; expands to all 26 families) ──

def families : List GenFamily := [
  { slug := "tag-block-payload", cases := [
      { name := "clear-emoji",       input := [0x1F600] },
      { name := "direct-ascii",      input := [0xE0041, 0xE0042] } ] },
  { slug := "variation-selector-payload", cases := [
      { name := "clear-registered-emoji", input := [0x1F600, 0xFE0F] },
      { name := "illegal-target",          input := [0x0041, 0xFE0F] } ] },
  { slug := "zero-width-payload", cases := [
      { name := "clear-emoji-zwj",  input := [0x1F468, 0x200D, 0x1F4BB] },
      { name := "binary-payload",    input := [0x48, 0x200B, 0x69, 0x200B, 0x69] } ] },
  { slug := "bidi-control-balance", cases := [
      { name := "clear-balanced",    input := [0x202A, 0x41, 0x202C] },
      { name := "lone-rlo",          input := [0x202E, 0x41] } ] },
  { slug := "homoglyph-confusable", cases := [
      { name := "clear-ascii",       input := [0x48, 0x65, 0x6C, 0x6C, 0x6F] },
      { name := "math-alpha",        input := [0x1D400] } ] },
  { slug := "mixed-script-admissibility", cases := [
      { name := "clear-ascii",       input := [0x48, 0x65, 0x6C, 0x6C, 0x6F] },
      { name := "latin-cyrillic",    input := [0x0061, 0x0440, 0x0061] } ] },
  { slug := "surrogate-reassembly", cases := [
      { name := "clear-valid-utf8",  input := [0xC3, 0xA9] },
      { name := "overlong",          input := [0xE0, 0x80, 0xAF] } ] },
  { slug := "admissibility-form-drift", cases := [
      { name := "clear-ascii-admin", input := [0x61, 0x64, 0x6D, 0x69, 0x6E] },
      { name := "fi-ligature-drift", input := [0xFB01] } ] },
  { slug := "identifier-form-drift", cases := [
      { name := "clear-greek-alpha", input := [0x03B1] },
      { name := "math-italic-shift", input := [0x1D44E] } ] },
  { slug := "confusable-bidi-compound", cases := [
      { name := "clear-cyrillic-alone", input := [0x0430] },
      { name := "rlo-cyrillic-compound", input := [0x202E, 0x0430] } ] },
  { slug := "covert-display-compound", cases := [
      { name := "clear-bidi-only",   input := [0x202E] },
      { name := "bidi-plus-vs",      input := [0x202E, 0x0041, 0xFE00] } ] },
  { slug := "case-expansion-mismatch", cases := [
      { name := "clear-ascii",       input := [0x48, 0x65, 0x6C, 0x6C, 0x6F] },
      { name := "sharp-s-upper",     input := [0x00DF] } ] },
  { slug := "locale-case-inversion", cases := [
      { name := "clear-ascii",       input := [0x48, 0x65, 0x6C, 0x6C, 0x6F] },
      { name := "capital-i-turkish", input := [0x0049] } ] },
  { slug := "nfc-idempotence-witness", cases := [
      { name := "clear-precomposed-e", input := [0x00E9] },
      { name := "decomposed-e",        input := [0x0065, 0x0301] } ] },
  { slug := "normalization-bomb", cases := [
      { name := "clear-hangul",      input := [0xD55C] },
      { name := "arabic-ligature-blowup", input := [0xFDFA] } ] },
  { slug := "stream-safe-violation", cases := [
      { name := "thirty-nonstarters-clear", input := List.replicate 30 0x0301 },
      { name := "thirtyone-nonstarters-overrun", input := (0x0061 :: List.replicate 31 0x0301) } ] },
  { slug := "width-class-confusion", cases := [
      { name := "clear-han",         input := [0x4E2D, 0x6587] },
      { name := "fullwidth-a",       input := [0xFF21] } ] },
  { slug := "renderer-divergence", cases := [
      { name := "clear-han",         input := [0x4E2D, 0x6587] },
      { name := "fullwidth-variance", input := [0xFF21] } ] },
  { slug := "rtl-injection", cases := [
      { name := "clear-digits",      input := [0x30, 0x31, 0x32, 0x33] },
      { name := "rlo-in-ltr",        input := [0x41, 0x202E, 0x42] } ] },
  { slug := "filename-disguise", cases := [
      { name := "clear-foo",         input := [0x66, 0x6F, 0x6F] },
      { name := "rlo-flip",          input := [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65] } ] },
  { slug := "source-display-divergence", cases := [
      { name := "clear-ascii",       input := [0x48, 0x65, 0x6C, 0x6C, 0x6F] },
      { name := "tag-block",         input := [0xE0041, 0xE0042] } ] },
  { slug := "ai-watermark-detectability", cases := [
      { name := "clear-ascii",       input := [0x61, 0x62, 0x63] },
      { name := "nnbsp-boundary",    input := [0x61, 0x202F, 0x62] } ] },
  { slug := "bip39-canonical", cases := [
      { name := "clear-empty",       input := [] },
      { name := "mixed-case",        input := [0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E] } ] },
  { slug := "hash-input-stability", cases := [
      { name := "clear-ascii",       input := [0x61, 0x62, 0x63] },
      { name := "trailing-space",    input := [0x61, 0x20] } ] },
  { slug := "skin-tone-variation-forgery", cases := [
      { name := "clear-wave-tone",   input := [0x1F44B, 0x1F3FB] },
      { name := "stacked-tones",     input := [0x1F44B, 0x1F3FB, 0x1F3FC] } ] },
  { slug := "emoji-zwj-integrity", cases := [
      { name := "clear-rgi-family",  input := [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466] },
      { name := "double-zwj",        input := [0x1F600, 0x200D, 0x200D, 0x1F600] } ] }
]

def main : IO Unit := do
  -- Non-destructive: write to a staging dir. Promotion into the live contract
  -- (fixtures/security/detectors/) happens once each family's vector set is curated
  -- to fully cover — never regress — the existing hand-authored cases.
  let outDir : System.FilePath := "dist/generated-fixtures/detectors"
  IO.FS.createDirAll outDir
  for f in families do
    IO.FS.writeFile (outDir / (f.slug ++ ".json")) (emitFamily f ++ "\n")
    IO.println s!"wrote {outDir}/{f.slug}.json  ({f.cases.length} cases)"

#eval main
