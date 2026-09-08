/-
  Unicode.Security.Identity.HomoglyphConfusableSpec

  Kernel spot-checks for the HomoglyphConfusable detector.

  These `decide +kernel` witnesses reduce the whole detection pipeline on concrete
  inputs, so they are the single heaviest cost in the detector's module tree. They
  are held here, apart from `Unicode.Security.Identity.HomoglyphConfusable`, so the
  detector's definitions — and every runtime and conformance module that consumes
  them — elaborate without paying for the kernel reductions. This module belongs to
  the assurance evidence tier, not the runtime security root.
-/

import Unicode.Security.Identity.HomoglyphConfusable
import Unicode.Normalization.LowCodepointNfc

namespace Unicode.Security.Identity.HomoglyphConfusable

set_option maxRecDepth 100000
set_option maxHeartbeats 8000000

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide +kernel

/-- NFC is the identity on the all-ASCII "Hello", so the decomposition-swap
    sub-check sees no divergence — established structurally, without reducing the
    composition table. -/
theorem hasDecompositionSwap_hello :
    hasDecompositionSwap [0x48, 0x65, 0x6C, 0x6C, 0x6F] = false := by
  unfold hasDecompositionSwap
  rw [Unicode.Normalization.LowCodepointNfc.toNFC_id_all_lt
        [0x48, 0x65, 0x6C, 0x6C, 0x6F] (by decide)]
  simp

/-- NFC is the identity on the all-ASCII "Nethereum". -/
theorem hasDecompositionSwap_nethereum :
    hasDecompositionSwap [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D] = false := by
  unfold hasDecompositionSwap
  rw [Unicode.Normalization.LowCodepointNfc.toNFC_id_all_lt
        [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D] (by decide)]
  simp

/-- Pure ASCII "Hello" is clear (no confusable structure). -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  unfold detect detectWithContext
  rw [hasDecompositionSwap_hello]
  decide +kernel

/-- The legitimate "Nethereum" (pure Latin) is clear. -/
theorem detect_nethereum_legit_clear :
    (detect [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]).classify.isClear = true := by
  unfold detect detectWithContext
  rw [hasDecompositionSwap_nethereum]
  decide +kernel

/-- The Nethereum Oct-2025 typosquat — final `е` (Cyrillic
    U+0435) replacing `e` (Latin U+0065) at position 6.  Iterated
    skeleton must match the canonical "Nethereum" target. -/
theorem detect_nethereum_attack :
    let cps : List Nat :=
      [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Lower-case variant of the Nethereum typosquat — `nethereum`
    with Cyrillic SMALL LETTER IE (U+0435) at position 6.  NuGet
    package IDs are case-insensitive, so this is the same
    threat-class as the title-case variant.  Under UTS #39 §5.4
    case folding (added to `Unicode.Confusables.skeleton`), the
    title-case target `Nethereum` and this lower-case attack both
    fold to lower-case `nethereum`, their skeletons agree, and
    `TargetMatch` fires with target attribution preserved. -/
theorem detect_nethereum_lowercase_attack :
    let cps : List Nat :=
      [0x6E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- ALL-CAPS variant of the Nethereum typosquat — `NETHEREUM`
    with Cyrillic CAPITAL LETTER IE (U+0415) at position 6.  Same
    case-insensitivity argument as `detect_nethereum_lowercase_attack`;
    under §5.4 case folding the all-caps attack also folds to
    lower-case `nethereum` and fires `TargetMatch`. -/
theorem detect_nethereum_uppercase_attack :
    let cps : List Nat :=
      [0x4E, 0x45, 0x54, 0x48, 0x45, 0x52, 0x0415, 0x55, 0x4D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- `EXPRESS` is the target `express` in capitals: no codepoint is a
    look-alike of another, so it is the same name and not a match. Plain ASCII
    with nothing else to report, the verdict is clear. -/
theorem detect_express_uppercase_clear :
    (detect [0x45, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53]).classify.isClear = true := by
  decide +kernel

/-- `Next` is the target `next` capitalised; clear for the same reason. -/
theorem detect_next_capitalised_clear :
    (detect [0x4E, 0x65, 0x78, 0x74]).classify.isClear = true := by
  decide +kernel

/-- `expreß` is not a case variant of `express` — `ß` has no simple case
    mapping to `ss` — while its case-folded skeleton is `express`, so the
    substitution the guard leaves alone is exactly the one `TargetMatch`
    exists to report. -/
theorem detect_express_sharp_s_target :
    (detect [0x65, 0x78, 0x70, 0x72, 0x65, 0x00DF]).classify.tag
      = some "TargetMatch" := by
  decide +kernel

/-- Base-letter + combining-mark confusable — `nɇthereum`, where the
    second letter is U+0247 LATIN SMALL LETTER E WITH STROKE whose
    UTS #39 confusable maps to the SEQUENCE `e + combining long
    solidus overlay`.  The §4+§5.4 skeleton (without combining-mark
    stripping) does NOT match the bare-letter `nethereum` target
    because of the inserted combining mark.  `letterSkeleton`
    (which strips combining marks from the skeleton output) catches
    it.  Mutation testing surfaced this class — 21% of single-
    codepoint mutations across the curated target set bypassed
    `iteratedSkeleton` via similar "letter + accent" entries. -/
theorem detect_nethereum_stroked_e_attack :
    let cps : List Nat :=
      [0x6E, 0x0247, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Base-letter + combining-mark confusable — `nehterħeum`, U+0127
    LATIN SMALL LETTER H WITH STROKE whose confusable maps to
    `h + combining short stroke overlay`.  Confirms `letterSkeleton`
    catches the H-variant of the same class. -/
theorem detect_nethereum_stroked_h_attack :
    let cps : List Nat :=
      [0x6E, 0x65, 0x74, 0x0127, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Zero-width insertion bypass — `net` + ZWSP (U+200B) + `hereum`.
    Without the `Default_Ignorable_Code_Point` filter in
    `letterSkeleton`, the inserted ZWSP survives into the
    comparison and breaks strict-equality match with the
    `nethereum` target.  Rust-port red-team confirmed: all six of
    {ZWSP, ZWNJ, ZWJ, WJ, BOM, NNBSP} inserted bypassed the prior
    detector (`Clear` verdict).  The default-ignorable filter
    closes the class. -/
theorem detect_nethereum_zwsp_insertion_attack :
    let cps : List Nat :=
      [0x6E, 0x65, 0x74, 0x200B, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Zero-width-joiner insertion variant — same class as
    `detect_nethereum_zwsp_insertion_attack` but with U+200D
    (ZWJ) which has CCC = 0 and is `Default_Ignorable`. -/
theorem detect_nethereum_zwj_insertion_attack :
    let cps : List Nat :=
      [0x6E, 0x65, 0x74, 0x200D, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Math-Alpha posing — `𝐀` (Mathematical Bold Capital A,
    U+1D400) by itself is flagged. -/
theorem detect_math_alpha :
    (detect [0x1D400]).classify.tag = some "MathAlpha" := by
  decide +kernel

/-- Fullwidth disguise — `Ｐａｙｐａｌ` (FF30 FF41 FF59 FF50 FF41 FF4C).
    With UTS #39 §5.4 case-folded skeleton the input case-folds and
    confusable-substitutes to lowercase ASCII `paypal`, which matches
    the curated `paypal` attack target; the higher-priority
    `TargetMatch` sub-threat fires before `WidthClass`, producing
    the strictly more informative classification (attacker is
    impersonating PayPal, not merely "input has fullwidth chars"). -/
theorem detect_fullwidth_paypal :
    let cps : List Nat :=
      [0xFF30, 0xFF41, 0xFF59, 0xFF50, 0xFF41, 0xFF4C]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- `admın` — dotless i U+0131 standing in for i in `admin`.  Single-script
    Latin, in NFC, and no curated target names `admin`, so every earlier rung
    clears it; confusables.txt maps ı to i (and m to the pair rn), so its
    skeleton is the all-ASCII `adrnin` — the same skeleton `admin` has, which is
    what makes the two confusable — and `AsciiConfusable` fires, localised to
    the substituted position. -/
theorem detect_dotless_i_admin :
    (detect [0x61, 0x64, 0x6D, 0x0131, 0x6E]).classify.tag = some "AsciiConfusable" := by
  decide +kernel

theorem detect_dotless_i_admin_position :
    (detect [0x61, 0x64, 0x6D, 0x0131, 0x6E]).classify.positions = [3] := by
  decide +kernel

/-- `straße` is clear: ß has no confusables row, so the case-preserving skeleton
    keeps it and the identifier is not a look-alike of any ASCII string.  Under
    the case-folded skeleton it would have read as `strasse`; this pins that the
    rung does not fold. -/
theorem detect_sharp_s_clear :
    (detect [0x73, 0x74, 0x72, 0x61, 0xDF, 0x65]).classify.isClear = true := by
  decide +kernel

/-- In running text the same `admın` is not judged by the rung: such a caller
    holds prose or source, where ASCII-skeleton punctuation is ordinary
    content. -/
theorem detectWithContext_running_text_dotless_i_clear :
    (detectWithContext { runningText := true } [0x61, 0x64, 0x6D, 0x0131, 0x6E]).classify.isClear
      = true := by
  decide +kernel

/-- As a token of running text, `admın` is still reported: a Latin token spelled
    with a non-ASCII Latin look-alike is an identifier posing as another. -/
theorem detectWithContext_token_dotless_i_admin :
    (detectWithContext { identifierToken := true } [0x61, 0x64, 0x6D, 0x0131, 0x6E]).classify.tag
      = some "AsciiConfusable" := by
  decide +kernel

/-- As a token of running text, the Greek variable `α` is content: it skeletons
    to ASCII `a`, but it is a Greek identifier, not a Latin one posing as
    another. -/
theorem detectWithContext_token_greek_alpha_clear :
    (detectWithContext { identifierToken := true } [0x03B1]).classify.isClear = true := by
  decide +kernel

/-- As a token of running text, `scоpe` with a Cyrillic о is the homograph
    shape and fires the cross-script rung. -/
theorem detectWithContext_token_cyrillic_o_scope :
    (detectWithContext { identifierToken := true } [0x73, 0x63, 0x043E, 0x70, 0x65]).classify.tag
      = some "CrossScriptMix" := by
  decide +kernel

/-- The identifier reading is `detectWithContext` at the default context. -/
theorem detect_eq_detectWithContext_default (input : List Nat) :
    detect input = detectWithContext {} input := rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 Predicate sanity checks
-- ═══════════════════════════════════════════════════════════════════════════════

theorem is_math_alpha_bold_A : isMathAlphanumeric 0x1D400 = true := by
  decide

theorem is_math_alpha_last : isMathAlphanumeric 0x1D7FF = true := by
  decide

theorem is_math_alpha_below : isMathAlphanumeric 0x1D3FF = false := by
  decide

theorem is_math_alpha_above : isMathAlphanumeric 0x1D800 = false := by
  decide

theorem is_fullwidth_A : isFullwidthHalfwidth 0xFF21 = true := by
  decide

theorem is_fullwidth_above : isFullwidthHalfwidth 0xFFF0 = false := by
  decide

theorem is_fullwidth_below : isFullwidthHalfwidth 0xFF00 = false := by
  decide
end Unicode.Security.Identity.HomoglyphConfusable
