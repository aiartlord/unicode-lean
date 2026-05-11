/-
  Unicode.Conformance.Security.RtlInjectionTokenizedTest

  Companion conformance proof for the v1.5 region-aware D3
  behaviour.  Folds the universal `Unicode.Security.Fixture`
  parser over `RtlInjectionTokenizedTest.txt` and
  `native_decide`-closes the predicate that every row's expected
  verdict matches what
  `Unicode.Security.Display.RtlInjection.detect` produces when
  invoked with `Language.rust`.

  The v1 conformance proof in `RtlInjectionTest.lean` continues
  to run the detector with the default `Language.none` and is
  unchanged by the v1.5 refactor.
-/

import Unicode.Security.Fixture
import Unicode.Security.Display.RtlInjection

namespace Unicode.Conformance.Security.RtlInjectionTokenizedTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Display.RtlInjection
open Unicode.Security.Display.SourceCodeTokenize (Language)

/-- Hand-curated v1.5 fixture for D3 under Rust tokenization.
    Clear rows demonstrate that bidi codepoints (format-controls
    or strong-RTL letters) sitting inside string literals or
    comments are filtered out.  Hazard rows demonstrate that
    bidi codepoints in code regions still fire D3. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/RtlInjectionTokenizedTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project a `D3Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : D3Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Run `detect r.input .rust` and check the verdict against the
    fixture's expected classification, sub-threat name, and
    positions. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input Language.rust
  let (kind, subTag) := projectClassify v.classify
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (v.classify.positions = r.expectedPositions)

/-- Every fixture row's detector verdict under `Language.rust`
    matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 16 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 7 := by native_decide

theorem covers_hazard :
    (rows.filter (·.sectionName = "Hazard")).size ≥ 7 := by native_decide

end Unicode.Conformance.Security.RtlInjectionTokenizedTest
