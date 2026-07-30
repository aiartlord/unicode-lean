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
      { name := "ascii-clear",       input := [72, 101, 108, 108, 111] },
      { name := "tag-ascii-payload", input := [0xE0041, 0xE0042] } ] },
  { slug := "stream-safe-violation", cases := [
      { name := "thirty-nonstarters-clear", input := List.replicate 30 0x0301 },
      { name := "thirtyone-nonstarters-overrun", input := (0x0061 :: List.replicate 31 0x0301) } ] }
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
