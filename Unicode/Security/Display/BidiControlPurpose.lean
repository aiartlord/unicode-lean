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
    * Every other codepoint is recorded against the innermost open span only:
      whether it is strong right-to-left (Bidi_Class R or AL), strong
      left-to-right (L), or ASCII code syntax (quotes, brackets, comment
      markers, separators, operators).  A nested span manages its own
      content, so an acronym isolated inside an Arabic embedding does not
      make the embedding mixed.
    * PDF closes the top span when it is an embedding; against an isolate on
      top, or an empty stack, it is an orphan.  PDI closes down to the
      innermost isolate, implicitly terminating the embeddings above it, which
      are thereby unbalanced; with no isolate open it is an orphan.
    * A closed span is purposeful iff its direct content is exactly its own
      direction and carries no code syntax: a right-to-left span with
      right-to-left text, no left-to-right text and no syntax; a left-to-right
      span in right-to-left context — inside an open right-to-left span, or
      in a paragraph whose first strong character is right-to-left (UAX #9
      P2/P3) — with left-to-right text, no right-to-left text and no syntax.
    * The positions reported are those of every orphan, every opener left
      open at the end of input, every embedding a PDI terminated implicitly,
      and both ends of every closed span that was not purposeful.

  FSI resolves its direction from its content, so a first-strong isolate
  around left-to-right text is a no-op; it is treated as right-to-left in
  effect and is purposeful only when its content is right-to-left text.

  What the rule admits is therefore exactly a span that renders its own text
  and nothing else: an Arabic literal, a Hebrew comment, a Latin acronym
  inside them.  Planting one right-to-left letter beside Latin code does not
  help an adversary — the span is mixed and is reported — and neither does
  swallowing a quote or a parenthesis into an otherwise Arabic span.  What
  remains outside the rule is a pure right-to-left span placed so that its
  own text lands somewhere misleading; that moves no code and no syntax, and
  the text is visible to the reviewer.

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

/-- ASCII code syntax: the codepoints a Trojan Source payload moves — quotes,
    brackets, comment markers, statement separators, operators.  Inside a
    right-to-left span they resolve right-to-left and change places on screen,
    so a span carrying one is not merely rendering right-to-left text.  Prose
    punctuation (period, comma, question mark, exclamation mark, colon, hyphen,
    low line), space and digits are not in the set: an Arabic sentence carries
    them and they move nothing a compiler reads. -/
def isCodeSyntax (cp : Nat) : Bool :=
  cp = 0x22 || cp = 0x27 || cp = 0x60 || cp = 0x28 || cp = 0x29 || cp = 0x5B ||
  cp = 0x5D || cp = 0x7B || cp = 0x7D || cp = 0x2F || cp = 0x5C || cp = 0x2A ||
  cp = 0x23 || cp = 0x3B || cp = 0x3C || cp = 0x3E || cp = 0x3D || cp = 0x2B ||
  cp = 0x7C || cp = 0x26 || cp = 0x25 || cp = 0x24 || cp = 0x40 || cp = 0x5E ||
  cp = 0x7E

/-- One open span: where it opened, how it closes, its direction in effect,
    and what has appeared directly inside it — strong right-to-left text,
    strong left-to-right text, ASCII code syntax. -/
structure OpenSpan where
  pos       : Nat
  isolate   : Bool
  rtlKind   : Bool
  sawRtl    : Bool
  sawLtr    : Bool
  sawSyntax : Bool
  deriving DecidableEq, Repr, Inhabited

/-- Record a codepoint against the innermost open span only.  A nested span
    manages its own content: a left-to-right acronym isolated inside an Arabic
    embedding is the inner span's business, and does not make the outer span
    mixed. -/
def markContent (stack : List OpenSpan) (cp : Nat) : List OpenSpan :=
  match stack with
  | [] => []
  | s :: below =>
    { s with
      sawRtl    := s.sawRtl || isStrongRTL cp,
      sawLtr    := s.sawLtr || isStrongLTR cp,
      sawSyntax := s.sawSyntax || isCodeSyntax cp } :: below

/-- True iff a span closing here sits in right-to-left context: an enclosing
    open span is right-to-left in effect, or the paragraph runs right-to-left. -/
def inRtlContext (enclosing : List OpenSpan) (paragraphRtl : Bool) : Bool :=
  paragraphRtl || enclosing.any (fun s => s.rtlKind)

/-- A closed span is purposeful iff it encloses text of exactly its own
    direction and nothing a compiler reads: a right-to-left span whose direct
    content has right-to-left text, no left-to-right text and no code syntax;
    or a left-to-right span in right-to-left context whose direct content has
    left-to-right text, no right-to-left text and no code syntax.  A single
    opposite-direction letter or one quote inside the span makes it a reorder
    of something other than its own text, and it is reported. -/
def spanPurposeful (s : OpenSpan) (enclosing : List OpenSpan) (paragraphRtl : Bool) : Bool :=
  if s.rtlKind then s.sawRtl && !s.sawLtr && !s.sawSyntax
  else inRtlContext enclosing paragraphRtl && s.sawLtr && !s.sawRtl && !s.sawSyntax

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
        ({ pos := idx, isolate := opensIsolateKind cp, rtlKind := opensRtlKind cp,
           sawRtl := false, sawLtr := false, sawSyntax := false } :: stack)
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
    else
      walk rest (idx + 1) (markContent stack cp) paragraphRtl acc

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

/-- A PDI terminates the embedding opened inside its isolate implicitly, so the
    embedding is unbalanced.  The Hebrew letter is the embedding's content, not
    the isolate's, so the isolate encloses nothing of its own and is purposeless
    too. -/
theorem purposeless_pdi_terminates_embedding :
    purposelessControlPositions [0x2067, 0x202B, 0x05D0, 0x2069] = [0, 1, 3] := by decide

/-- One right-to-left letter planted beside Latin text does not legitimise the
    span: the content mixes directions, so both ends are reported. -/
theorem purposeless_rle_planted_letter :
    purposelessControlPositions [0x202B, 0x61, 0x62, 0x0645, 0x202C] = [0, 4] := by decide

/-- Code syntax inside a right-to-left span — here a quote and a parenthesis
    beside an Arabic letter — is the commenting-out shape, and is reported. -/
theorem purposeless_rle_with_syntax :
    purposelessControlPositions [0x202B, 0x0645, 0x22, 0x29, 0x202C] = [0, 4] := by decide

/-- A left-to-right acronym isolated inside an Arabic embedding: the inner span
    encloses left-to-right text in right-to-left context, the outer encloses
    Arabic and the inner span, and both are purposeful. -/
theorem purposeful_nested_acronym :
    purposelessControlPositions
      [0x202B, 0x0645, 0x202A, 0x47, 0x50, 0x55, 0x202C, 0x0631, 0x202C] = [] := by decide

/-- `hasPurposelessControl` and `firstPurposelessControl` read the same list. -/
theorem first_of_lone_rlo :
    firstPurposelessControl [0x41, 0x202E, 0x42] = some (1, 0x202E) := by decide

theorem has_none_for_arabic_literal :
    hasPurposelessControl [0x22, 0x202B, 0x0645, 0x0631, 0x202C, 0x22] = false := by decide

end Unicode.Security.Display.BidiControlPurpose
