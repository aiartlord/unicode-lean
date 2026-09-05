/-
  Unicode.Security.Display.BidiControlPurpose

  Which bidi format controls in an input serve a purpose, and which do not.

  The nine UAX #9 format controls exist to manage right-to-left text: an
  embedding, isolate or override span is doing that job when the text it
  encloses is right-to-left, or when it forces left-to-right text inside a
  right-to-left context.  A span that encloses no strong right-to-left
  character in a left-to-right context manages nothing — `LRI user PDI`
  around Latin text, `LRO return PDF` around a keyword — and an unbalanced
  control never manages anything.  Every Trojan Source payload (Boucher and
  Anderson, CVE-2021-42574) is a control of that kind: the reordering it
  buys is the divergence between what a reviewer sees and what a compiler
  parses, and it has no right-to-left text to justify it.  A balanced
  embedding around an Arabic string literal is the opposite case: it renders
  the literal as written, which is what the control is for.

  This is not source-region filtering.  The question is asked of every
  control wherever it sits — code, string literal, comment — and it is a
  property of the control span itself, decided from the codepoints it
  encloses, never from where a tokenizer would place it.  A purposeless
  control in a comment is reported exactly as one in code.

  Rule.  Walk the input keeping the stack of open spans.

    * An opener pushes a span recording its position, whether it is an
      isolate (closed by PDI) or an embedding/override (closed by PDF), and
      whether it is right-to-left in effect (RLE, RLO, RLI, FSI) or
      left-to-right (LRE, LRO, LRI).
    * A strong right-to-left codepoint (Bidi_Class R or AL) marks every open
      span as having seen right-to-left text.
    * PDF closes the top span when it is an embedding; against an isolate on
      top, or an empty stack, it is an orphan.  PDI closes down to the
      innermost isolate, implicitly terminating the embeddings above it, which
      are thereby unbalanced; with no isolate open it is an orphan.
    * A closed right-to-left span is purposeful iff it saw right-to-left text.
      A closed left-to-right span is purposeful iff it sits in right-to-left
      context: inside an open right-to-left span, or in a paragraph whose
      first strong character is right-to-left (UAX #9 P2/P3).
    * The positions reported are those of every orphan, every opener left
      open at the end of input, every embedding a PDI terminated implicitly,
      and both ends of every closed span that was not purposeful.

  FSI resolves its direction from its content, so a first-strong isolate
  around left-to-right text is a no-op; it is treated as right-to-left in
  effect and is purposeful only when its content has right-to-left text.

  Residual.  A single right-to-left letter inside an embedding makes the
  embedding purposeful, so an adversary can legitimise a span by planting
  one.  The letter is then visible to the reviewer, and the confusable and
  compound detectors still see it; what this rule removes is the silent
  case, where a control span carries nothing that could explain it.

  The consumers are the bidi constituent of `SourceDisplayDivergence`, the
  bidi rung of `FilenameDisguise`, the control positions
  `ConfusableBidiCompound` pairs with a confusable, and the control rung of
  `RtlInjection` for a field of running text.  `BidiControlBalance` is
  unchanged: its verdict is balance, and this rule is strictly stronger.
-/

import Unicode.TrojanSource
import Unicode.Bidi.Algorithm

namespace Unicode.Security.Display.BidiControlPurpose

open Unicode.Generated.DerivedBidiClass (BidiClass)
open Unicode.TrojanSource (isPDF isPDI)

-- The spot checks reduce `lookupBidiClass` decision trees per codepoint.
set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Codepoint predicates
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff the codepoint's `Bidi_Class` is strong right-to-left (R or AL). -/
@[inline]
def isStrongRTL (cp : Nat) : Bool :=
  match Unicode.Bidi.Algorithm.lookupBidiClass cp with
  | .R       => true
  | .AL      => true
  | otherBc  => Function.const BidiClass false otherBc

/-- True iff the codepoint's `Bidi_Class` is strong left-to-right (L). -/
@[inline]
def isStrongLTR (cp : Nat) : Bool :=
  match Unicode.Bidi.Algorithm.lookupBidiClass cp with
  | .L       => true
  | otherBc  => Function.const BidiClass false otherBc

/-- True iff `cp` opens a span that is right-to-left in effect: RLE, RLO, RLI,
    or FSI (whose direction resolves from its content). -/
def opensRtlKind (cp : Nat) : Bool :=
  cp = 0x202B || cp = 0x202E || cp = 0x2067 || cp = 0x2068

/-- True iff `cp` opens a span that is left-to-right in effect: LRE, LRO, LRI. -/
def opensLtrKind (cp : Nat) : Bool :=
  cp = 0x202A || cp = 0x202D || cp = 0x2066

/-- True iff `cp` opens an isolate (closed by PDI rather than PDF). -/
def opensIsolateKind (cp : Nat) : Bool :=
  cp = 0x2066 || cp = 0x2067 || cp = 0x2068

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 The span stack
-- ═══════════════════════════════════════════════════════════════════════════════

/-- One open span: where it opened, how it closes, its direction in effect,
    and whether right-to-left text has appeared inside it. -/
structure OpenSpan where
  pos     : Nat
  isolate : Bool
  rtlKind : Bool
  sawRtl  : Bool
  deriving DecidableEq, Repr, Inhabited

/-- Record that a strong right-to-left codepoint appeared: every open span
    encloses it. -/
def markRtl (stack : List OpenSpan) : List OpenSpan :=
  stack.map (fun s => { s with sawRtl := true })

/-- True iff a span closing here sits in right-to-left context: an enclosing
    open span is right-to-left in effect, or the paragraph runs right-to-left. -/
def inRtlContext (enclosing : List OpenSpan) (paragraphRtl : Bool) : Bool :=
  paragraphRtl || enclosing.any (fun s => s.rtlKind)

/-- A closed span is purposeful iff it managed right-to-left text: a
    right-to-left span that saw some, or a left-to-right span in right-to-left
    context. -/
def spanPurposeful (s : OpenSpan) (enclosing : List OpenSpan) (paragraphRtl : Bool) : Bool :=
  if s.rtlKind then s.sawRtl else inRtlContext enclosing paragraphRtl

/-- Pop to the innermost isolate.  Returns the embeddings above it (which a
    PDI terminates implicitly), the isolate itself, and the stack below it;
    `none` when no isolate is open. -/
def popToIsolate : List OpenSpan → Option (List OpenSpan × OpenSpan × List OpenSpan)
  | [] => none
  | s :: below =>
    if s.isolate then some ([], s, below)
    else
      match popToIsolate below with
      | none => none
      | some (dropped, iso, rest) => some (s :: dropped, iso, rest)

/-- UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
    character is right-to-left. -/
def paragraphIsRtl (input : List Nat) : Bool :=
  match input.find? (fun cp => isStrongRTL cp || isStrongLTR cp) with
  | some cp => isStrongRTL cp
  | none    => false

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 The walk
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Walk the remaining input at index `idx` with the open-span `stack`,
    accumulating the positions of purposeless controls in `acc`.  At the end
    of input every span still open is unbalanced and therefore purposeless. -/
def walk : List Nat → Nat → List OpenSpan → Bool → List Nat → List Nat
  | [], idx, stack, paragraphRtl, acc =>
    Function.const (Nat × Bool) (acc ++ stack.map (fun s => s.pos)) (idx, paragraphRtl)
  | cp :: rest, idx, stack, paragraphRtl, acc =>
    if opensRtlKind cp || opensLtrKind cp then
      walk rest (idx + 1)
        ({ pos := idx, isolate := opensIsolateKind cp,
           rtlKind := opensRtlKind cp, sawRtl := false } :: stack)
        paragraphRtl acc
    else if isPDF cp then
      match stack with
      | s :: below =>
        if s.isolate then
          -- PDF against an open isolate closes nothing (UAX #9 X7): an orphan.
          walk rest (idx + 1) stack paragraphRtl (acc ++ [idx])
        else
          walk rest (idx + 1) below paragraphRtl
            (if spanPurposeful s below paragraphRtl then acc else acc ++ [s.pos, idx])
      | [] => walk rest (idx + 1) [] paragraphRtl (acc ++ [idx])
    else if isPDI cp then
      match popToIsolate stack with
      | none => walk rest (idx + 1) stack paragraphRtl (acc ++ [idx])
      | some (dropped, iso, below) =>
        walk rest (idx + 1) below paragraphRtl
          (acc ++ dropped.map (fun s => s.pos)
             ++ (if spanPurposeful iso below paragraphRtl then [] else [iso.pos, idx]))
    else if isStrongRTL cp then
      walk rest (idx + 1) (markRtl stack) paragraphRtl acc
    else
      walk rest (idx + 1) stack paragraphRtl acc

/-- Positions of the purposeless bidi format controls in `input`, in input
    order.  Empty iff every control in the input is balanced and manages
    right-to-left text. -/
def purposelessControlPositions (input : List Nat) : List Nat :=
  let raw := walk input 0 [] (paragraphIsRtl input) []
  input.zipIdx.filterMap (fun cpWithIdx =>
    if raw.contains cpWithIdx.2 then some cpWithIdx.2 else none)

/-- True iff `input` carries at least one purposeless bidi format control. -/
def hasPurposelessControl (input : List Nat) : Bool :=
  !(purposelessControlPositions input).isEmpty

/-- Position and codepoint of the first purposeless control, if any. -/
def firstPurposelessControl (input : List Nat) : Option (Nat × Nat) :=
  match purposelessControlPositions input with
  | []        => none
  | p :: tail => Function.const (List Nat) (some (p, input.getD p 0)) tail

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- No controls, no purposeless controls. -/
theorem purposeless_empty : purposelessControlPositions [] = [] := by decide

theorem purposeless_plain_mixed_text :
    purposelessControlPositions [0x41, 0x05D0] = [] := by decide

/-- A balanced empty isolate manages nothing: both ends are purposeless.  This
    is the case `SourceDisplayDivergence.detect_balanced_bidi_fires` pins. -/
theorem purposeless_balanced_empty_isolate :
    purposelessControlPositions [0x2066, 0x2069] = [0, 1] := by decide

/-- A lone RLO is unbalanced. -/
theorem purposeless_lone_rlo :
    purposelessControlPositions [0x202E, 0x41] = [0] := by decide

/-- RLE around Latin text in a left-to-right paragraph: right-to-left in effect
    with nothing right-to-left inside.  Both ends are purposeless. -/
theorem purposeless_rle_around_latin :
    purposelessControlPositions [0x41, 0x202B, 0x42, 0x202C] = [1, 3] := by decide

/-- RLE around an Arabic letter: the embedding manages right-to-left text and
    is purposeful, so the input carries no purposeless control. -/
theorem purposeful_rle_around_arabic :
    purposelessControlPositions [0x41, 0x202B, 0x0645, 0x202C, 0x42] = [] := by decide

/-- LRE around Latin text inside a right-to-left paragraph (Hebrew first): the
    left-to-right span sits in right-to-left context and is purposeful. -/
theorem purposeful_lre_in_rtl_paragraph :
    purposelessControlPositions [0x05D0, 0x202A, 0x41, 0x202C] = [] := by decide

/-- LRO around a Latin keyword in a left-to-right paragraph — the shape of the
    Trojan Source early-return variant written with U+202D and U+202C.  Both
    ends are purposeless. -/
theorem purposeless_lro_around_latin :
    purposelessControlPositions [0x202D, 0x72, 0x202C] = [0, 2] := by decide

/-- LRI around Latin text inside quotes — the stretched-string shape.  Both
    ends are purposeless. -/
theorem purposeless_lri_around_latin :
    purposelessControlPositions [0x22, 0x2066, 0x20, 0x75, 0x2069, 0x22] = [1, 4] := by decide

/-- A PDF with nothing open is an orphan. -/
theorem purposeless_orphan_pdf :
    purposelessControlPositions [0x41, 0x202C] = [1] := by decide

/-- A PDI terminates the embedding opened inside its isolate implicitly; the
    isolate itself saw Hebrew and is purposeful, the embedding is unbalanced. -/
theorem purposeless_pdi_terminates_embedding :
    purposelessControlPositions [0x2067, 0x202B, 0x05D0, 0x2069] = [1] := by decide

/-- `hasPurposelessControl` and `firstPurposelessControl` read the same list. -/
theorem first_of_lone_rlo :
    firstPurposelessControl [0x41, 0x202E, 0x42] = some (1, 0x202E) := by decide

theorem has_none_for_arabic_literal :
    hasPurposelessControl [0x22, 0x202B, 0x0645, 0x0631, 0x202C, 0x22] = false := by decide

end Unicode.Security.Display.BidiControlPurpose
