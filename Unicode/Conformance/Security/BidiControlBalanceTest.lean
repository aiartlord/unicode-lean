/-
  Unicode.Conformance.Security.BidiControlBalanceTest

  Conformance proof for the C5 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `BidiControlBalanceTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Covert.BidiControlBalance.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Covert.BidiControlBalance

namespace Unicode.Conformance.Security.BidiControlBalanceTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Covert.BidiControlBalance

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Raw fixture + parsed rows
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Hand-curated v1 fixture for C5 — 18 rows across 4 sections
    covering the Boucher-Anderson 2021 Trojan-Source shape (lone
    RLO, lone LRE), the CVE-2021-42694 isolate variants, orphan
    pops, and the legitimate-RTL balanced cases. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/BidiControlBalanceTest.txt"

/-- All parsed rows from the bundled fixture. -/
def rows : Array Row := parseFixture rawFixture

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Per-family classification-name mapping
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project a `C5Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : C5Classification) : ClassificationKind × Option String :=
  match c with
  | .clear => (.clear, none)
  | .hazard sub _ _ =>
    let tag : String := match sub with
      | .depthExceeded       _      => "DepthExceeded"
      | .orphanPop           _      => "OrphanPop"
      | .unbalancedEmbedding _ _    => "UnbalancedEmbedding"
      | .unbalancedIsolate   _ _    => "UnbalancedIsolate"
    (.hazard, some tag)

/-- Project a `C5Classification` to the positions array. -/
def projectPositions (c : C5Classification) : Array Nat :=
  match c with
  | .clear           => #[]
  | .hazard _ pos _  => pos

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-row verifier
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name, and
    hazard positions. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Headline conformance theorem + row-count gate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate (catches fixture corruption / accidental rewrites). -/
theorem row_count : rows.size = 18 := by native_decide

/-- Section coverage gates. -/
theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 7 := by native_decide

theorem covers_unbalanced_embedding :
    (rows.filter (·.sectionName = "UnbalancedEmbedding")).size ≥ 4 := by
  native_decide

theorem covers_unbalanced_isolate :
    (rows.filter (·.sectionName = "UnbalancedIsolate")).size ≥ 3 := by
  native_decide

theorem covers_orphan_pop :
    (rows.filter (·.sectionName = "OrphanPop")).size ≥ 4 := by native_decide

/-- The actual Trojan Source attack codepoint (RLO) is caught
    by the detector — regression check against the bug that
    was discovered and fixed during C5 development
    (Unicode.TrojanSource.opensEmbedding originally omitted RLO). -/
theorem detect_rlo_attack :
    (detect #[0x69, 0x66, 0x20, 0x202E, 0x29, 0x7B]).classify matches
      .hazard (.unbalancedEmbedding _ _) _ _ := by
  native_decide

end Unicode.Conformance.Security.BidiControlBalanceTest
