/-
  Unicode.Idna.Process

  UTS #46 §4 — IDNA Compatible Preprocessing. Implements the full
  ToUnicode and ToASCII algorithms by composing:

      mapping pass  →  NFC  →  label split  →  per-label Punycode  →  rejoin

  Each of the four UTS #46 input flags — `CheckHyphens`, `CheckBidi`,
  `CheckJoiners`, `UseSTD3ASCIIRules` — is exposed via the `Options`
  record and threaded through `toUnicode`, `toAscii`, and
  `toAsciiTransitional`. The default profile (`defaultOptions`) sets
  every flag to `true`, matching RFC 5891 strict semantics.
-/

import Unicode.Idna.Map
import Unicode.Idna.Punycode
import Unicode.Idna.CheckJoiners
import Unicode.Normalization.NFC
import Unicode.Normalization.Lookup
import Unicode.Precis.BidiRule
import Unicode.Generated.DerivedGeneralCategory

namespace Unicode.Idna.Process

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 LABEL SPLIT / JOIN
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Split codepoints at every U+002E ('.'); the dots are consumed.
    `splitLabels [a, '.', b, '.', c] = [[a], [b], [c]]`. The result
    always has at least one element. -/
def splitLabels (cps : List Nat) : List (List Nat) := Id.run do
  let mut labels  : List (List Nat) := []
  let mut current : List Nat         := []
  for cp in cps do
    if cp = 0x002E then
      labels := labels ++ [current]
      current := []
    else
      current := current ++ [cp]
  labels := labels ++ [current]
  return labels

/-- Join labels with U+002E ('.'). -/
def joinLabels (labels : List (List Nat)) : List Nat := Id.run do
  let mut acc   : List Nat := []
  let mut first : Bool      := true
  for label in labels do
    if first then
      first := false
    else
      acc := acc ++ [0x002E]
    acc := acc ++ label
  return acc

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 ASCII / UNICODE BRIDGE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Convert a `String` to `List Nat` by mapping each char to its codepoint. -/
def stringToCps (s : String) : List Nat :=
  s.toList.map (fun c => c.toNat)

/-- Convert a list of ASCII codepoints (assumed `< 0x80`) to a `String`. -/
def asciiCpsToString (cps : List Nat) : String :=
  String.ofList (cps.map Char.ofNat)

/-- True iff every codepoint is in the ASCII range. -/
def allAscii (cps : List Nat) : Bool := cps.all (· < 0x80)

/-- True iff `label` starts with the literal codepoints 'x','n','-','-'. -/
def hasXnPrefix (label : List Nat) : Bool :=
  Nat.ble 4 label.length
    && label[0]? == some 0x78
    && label[1]? == some 0x6E
    && label[2]? == some 0x2D
    && label[3]? == some 0x2D

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 OPTIONS  (UTS #46 §4 input flags)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- UTS #46 §4 IDNA preprocessing options. Each flag toggles a
    spec-defined check; the strict (RFC 5891-aligned) profile is
    `defaultOptions` with every flag enabled. -/
structure Options where
  /-- §4.1 step 3 — reject hyphen-position violations: hyphens at
      label positions 3 and 4 of a non-`xn--` label, or as the first
      or last codepoint of any label. -/
  checkHyphens      : Bool
  /-- §4.2 step 4 — reject Bidi-domain labels failing RFC 5893 §2. -/
  checkBidi         : Bool
  /-- §4.2 step 5 — reject labels failing the CONTEXTJ joiner rules
      for U+200C ZERO WIDTH NON-JOINER and U+200D ZERO WIDTH JOINER. -/
  checkJoiners      : Bool
  /-- §4.1 step 4 / RFC 1123 — reject labels containing ASCII
      codepoints outside the LDH set (a-z, 0-9, hyphen-minus). -/
  useSTD3ASCIIRules : Bool
  /-- §4.4 — reject when any label length is outside [1, 63] or the
      total domain length is outside [1, 253]. The toUnicode form is
      checked in codepoints; the toASCII form is checked in octets
      (which equals codepoints for ASCII output). -/
  verifyDnsLength   : Bool
  deriving Repr, Inhabited

/-- Strict-profile defaults: every UTS #46 check enabled. -/
def defaultOptions : Options :=
  { checkHyphens      := true
    checkBidi         := true
    checkJoiners      := true
    useSTD3ASCIIRules := true
    verifyDnsLength   := true }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 LABEL VALIDITY  (UTS #46 §4.1)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A label fails the hyphen-position rule when both characters at
    positions 3 and 4 (1-indexed; 2 and 3 zero-indexed) are '-'.
    Per UTS #46 §4.1 V2 the rule applies to the *decoded* label
    form; legitimate Punycode labels (e.g. `xn--fa-hia` for `faß`)
    decode to Unicode with no hyphens at those positions and so
    pass naturally, while a label whose decoded form happens to
    have ASCII hyphens at 3+4 (e.g. a maliciously-chained
    `xn--xn--a--gua`) is rejected. -/
def violatesHyphenRule (label : List Nat) : Bool :=
  Nat.ble 4 label.length
    && label[2]? == some 0x2D
    && label[3]? == some 0x2D

/-- A label fails the leading/trailing-hyphen rule when its first or
    last character is '-'. -/
def violatesLeadTrailHyphen (label : List Nat) : Bool :=
  (label[0]? == some 0x2D) || (label[label.length - 1]? == some 0x2D)

/-- A label fails the leading-combining-mark rule (UTS #46 §4.1
    V5) when its first codepoint has General_Category in
    `{Mn, Mc, Me}`. The General_Category check catches spacing
    combining marks (Mc) that have canonical_combining_class = 0
    — a class of codepoint that a `ccc ≠ 0` heuristic would
    silently accept. -/
def violatesLeadingCombiner (label : List Nat) : Bool :=
  match label[0]? with
  | none    => false
  | some cp =>
    match Unicode.Generated.DerivedGeneralCategory.lookup cp with
    | .Mn | .Mc | .Me => true
    | .Lu | .Ll | .Lt | .Lm | .Lo
    | .Nd | .Nl | .No
    | .Pc | .Pd | .Ps | .Pe | .Pi | .Pf | .Po
    | .Sm | .Sc | .Sk | .So
    | .Zs | .Zl | .Zp
    | .Cc | .Cf | .Cs | .Co | .Cn => false

/-- The STD3 LDH set: lowercase ASCII letter, ASCII digit, or
    hyphen-minus. Uppercase ASCII letters are excluded because the
    IDNA mapping pass maps them to lowercase before this check
    runs; their presence here is itself an STD3 violation. -/
def isLDH (cp : Nat) : Bool :=
  (0x61 ≤ cp && cp ≤ 0x7A)
    || (0x30 ≤ cp && cp ≤ 0x39)
    || cp == 0x2D

/-- A label fails STD3 ASCII rules when any of its ASCII codepoints
    fall outside the LDH set. Non-ASCII codepoints are unrestricted
    by this check. -/
def violatesSTD3 (label : List Nat) : Bool :=
  label.any (fun cp => cp < 0x80 && ! isLDH cp)

/-- A label is valid under `opts` if it passes the leading-combiner
    rule unconditionally, the hyphen rules when `checkHyphens` is
    set, and the STD3 LDH rule when `useSTD3ASCIIRules` is set. The
    label must additionally be in NFC; we ensure this upstream by
    normalising before label splitting. -/
def isValidLabel (opts : Options) (label : List Nat) : Bool :=
  ! decide (violatesLeadingCombiner label)
    && (! opts.checkHyphens
          || (! violatesHyphenRule label && ! violatesLeadTrailHyphen label))
    && (! opts.useSTD3ASCIIRules || ! violatesSTD3 label)

/-- UTS #46 §4.2 step 4 (CheckBidi). A domain is "bidi" if any of its
    labels contains an R, AL, or AN codepoint. For a bidi domain,
    every label — including labels with no RTL characters — must
    satisfy the strict variant of RFC 5893 §2 that does not
    short-circuit on non-Bidi labels. For a non-bidi domain the
    check is vacuously satisfied. -/
def checkBidi (labels : List (List Nat)) : Bool :=
  let isBidiDomain := labels.any Unicode.Precis.BidiRule.isBidiLabel
  ! isBidiDomain || labels.all Unicode.Precis.BidiRule.satisfiesBidiRuleStrict

/-- True iff the domain length is in [1, 253] codepoints. This is the
    domain-length half of UTS #46 §4.2 step 4, which `IdnaTestV2.txt` names
    `A4_1`. The file's own rows separate the two halves: a row carrying `A4_1`
    and not `A4_2` holds several labels each within 63 whose join exceeds 253.

    A trailing root dot is not part of the length. RFC 1035 measures the name
    without its empty root label, so `a.` counts as one character and the bare
    root `.` counts as none, which is why the file reports `A4_1` for `.` and
    withholds it from a 254-character name whose last character is the dot. -/
def totalLengthOk (output : List Nat) : Bool :=
  let measured :=
    if output.getLast? == some 0x2E then output.length - 1 else output.length
  Nat.ble 1 measured && Nat.ble measured 253

/-- True iff every label has length in [1, 63] codepoints. This is the
    label-length half of UTS #46 §4.2 step 4, which `IdnaTestV2.txt` names
    `A4_2`: a row carrying `A4_2` and not `A4_1` holds one label whose Punycode
    form exceeds 63. -/
def labelsLengthOk (labels : List (List Nat)) : Bool :=
  labels.all (fun l => Nat.ble 1 l.length && Nat.ble l.length 63)

/-- True iff `labels` contains an empty label that is not the
    final (trailing) one. A single trailing empty label is allowed
    as the fully-qualified-domain root dot (per UTS #46 / RFC 5891
    convention); empty labels in any earlier position are validity
    violations (`V4` or equivalent). -/
def hasNonTrailingEmptyLabel (labels : List (List Nat)) : Bool :=
  let n := labels.length
  if Nat.ble n 1 then false
  else (labels.take (n - 1)).any (fun l => l.length = 0)

/-- True iff the decoded label array satisfies every UTS #46 check
    enabled in `opts`: per-label validity, the CheckJoiners CONTEXTJ
    rule, the domain-level CheckBidi guard, and the
    no-non-trailing-empty-label rule. Length constraints are
    applied at each operation's output stage instead, since
    toUnicode and toASCII apply different subsets (`X4_2` only vs
    `A4_1` + `A4_2`). -/
def labelsPass (opts : Options) (decoded : List (List Nat)) : Bool :=
  decoded.all (isValidLabel opts)
    && (! opts.checkJoiners    || decoded.all CheckJoiners.checkJoiners)
    && (! opts.checkBidi       || checkBidi decoded)
    && ! hasNonTrailingEmptyLabel decoded

/-- The status codes one label raises, from the same predicates `isValidLabel`
    consults. `IdnaTestV2.txt` states a set of codes per row, so a conformance
    comparison needs which check failed and not only that one did.

    The `Options` flags select the codes, as the file's own header sets out:
    CheckHyphens governs `V2` and `V3`, UseSTD3ASCIIRules governs `U1`. -/
def labelStatuses (opts : Options) (label : List Nat) : List Map.Status :=
  (if violatesLeadingCombiner label then [Map.Status.V6] else [])
    ++ (if opts.checkHyphens && violatesHyphenRule label then [Map.Status.V2] else [])
    ++ (if opts.checkHyphens && violatesLeadTrailHyphen label then [Map.Status.V3] else [])
    ++ (if hasXnPrefix label then [Map.Status.V4] else [])
    ++ (if opts.useSTD3ASCIIRules && violatesSTD3 label then [Map.Status.U1] else [])

/-- The CONTEXTJ codes one label raises. `CheckJoiners.contextJViolations`
    numbers the RFC 5892 appendices; `1` is A.1, reported as `C1`, and `2` is
    A.2, reported as `C2`. -/
def labelJoinerStatuses (label : List Nat) : List Map.Status :=
  (CheckJoiners.contextJViolations label).filterMap (fun n =>
    if n == 1 then some Map.Status.C1
    else if n == 2 then some Map.Status.C2
    else none)

/-- The Bidi codes a domain raises. `BidiRule.bidiRuleViolationsStrict` numbers
    the RFC 5893 §2 rules; rule `n` is reported as `Bn`. A non-bidi domain
    raises none, matching `checkBidi`. -/
def domainBidiStatuses (labels : List (List Nat)) : List Map.Status :=
  let isBidiDomain := labels.any Unicode.Precis.BidiRule.isBidiLabel
  if ! isBidiDomain then []
  else
    (labels.flatMap Unicode.Precis.BidiRule.bidiRuleViolationsStrict).filterMap
      (fun n =>
        if n == 1 then some Map.Status.B1
        else if n == 2 then some Map.Status.B2
        else if n == 3 then some Map.Status.B3
        else if n == 4 then some Map.Status.B4
        else if n == 5 then some Map.Status.B5
        else if n == 6 then some Map.Status.B6
        else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 TOUNICODE  (UTS #46 §4.2)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff every codepoint of `cps` has IDNA disposition Valid
    or Deviation. UTS #46 §4.1 V6 (Nontransitional Processing):
    each code point in the (decoded) label must be either Valid
    or Deviation; Mapped / Ignored / Disallowed codepoints fail.
    The mapping pass earlier in `toUnicode` already handles these
    on the input side, but Punycode-decoded forms have not been
    through mapping and must be checked separately. -/
def decodedLabelValidV6 (cps : List Nat) : Bool :=
  cps.all (fun cp =>
    match Unicode.Idna.Disposition.disposition cp with
    | .Valid | .Deviation => true
    | .Mapped | .Ignored | .Disallowed => false)

/-- True iff every codepoint of `cps` is in the ASCII range
    (< 0x80). An xn-- label whose decoded form is all-ASCII is
    invalid per UTS #46 §4.2 step 4: re-encoding the decoded
    pure-ASCII content as Punycode would not produce the
    original `xn--` form, so the input was a malformed
    Punycode wrapper around content that needed no encoding. -/
def isAllAsciiCps (cps : List Nat) : Bool :=
  cps.all (fun cp => Nat.ble cp 0x7F)

/-- Decode a single label whose first four codepoints are 'xn--' via
    Punycode. Validity tied to UTS #46 §4.2 step 4 + §4.1 step 5
    + §4.1 V6:

      * Punycode decode failure  → output is the original label
                                    preserved, hasErrors=true (the
                                    spec requires the implementation
                                    to "record an error and not
                                    transform" on a malformed
                                    Punycode body — the original
                                    bytes carry forward unchanged).
      * Empty Punycode body      → output empty, hasErrors=true
                                    (`xn--` alone decodes to the
                                    empty sequence, which is itself
                                    a validity violation downstream).
      * Decoded all-ASCII        → output decoded, hasErrors=true
                                    (the xn-- wrapper is redundant /
                                    malformed; re-encoding pure
                                    ASCII produces a different
                                    Punycode result than the input).
      * Decoded not in NFC       → output decoded, hasErrors=true
                                    (UTS #46 §4.1 step 5).
      * Decoded contains a
        non-Valid /
        non-Deviation cp         → output decoded, hasErrors=true
                                    (V6).
      * Otherwise                → output decoded, hasErrors=false.

    On a non-`xn--` label the input is returned unchanged with
    no error. -/
def decodeLabel (label : List Nat) : Map.Result :=
  if hasXnPrefix label then
    let suffixSize := label.length - 4
    let suffix := asciiCpsToString (label.drop 4)
    match Punycode.decode suffix with
    | none         =>
      { output := label, hasErrors := true, statuses := [Map.Status.P4] }
    | some decoded =>
      if decoded.isEmpty then
        -- `xn--` exactly (empty suffix) decodes to the empty
        -- sequence; an `xn--` with non-empty suffix that
        -- nevertheless yields an empty decoded form is malformed,
        -- and the spec preserves the original bytes for downstream
        -- validity checks.
        if suffixSize = 0 then
          { output := [], hasErrors := true, statuses := [Map.Status.P4] }
        else
          { output := label, hasErrors := true, statuses := [Map.Status.P4] }
      else
        -- A decoded form that is entirely ASCII means the label was
        -- Punycode-encoded when it had no need to be, which UTS #46 §4.2
        -- rejects; the file reports it with the decoding failure code.
        let asciiOnly := isAllAsciiCps decoded
        let nfcOk := Unicode.Normalization.NFC.toNFC decoded == decoded
        let dispositionOk := decodedLabelValidV6 decoded
        { output := decoded
          hasErrors := asciiOnly || ! (nfcOk && dispositionOk)
          statuses :=
            (if asciiOnly then [Map.Status.P4] else [])
              ++ (if nfcOk then [] else [Map.Status.V1])
              ++ (if dispositionOk then [] else [Map.Status.V7]) }
  else
    { output := label, hasErrors := false }

/-- Decode every label in `labels`, joining their `hasErrors` flags. -/
def decodeLabels (labels : List (List Nat)) :
    List (List Nat) × Bool := Id.run do
  let mut decoded : List (List Nat) := []
  let mut errs    : Bool              := false
  for label in labels do
    let r := decodeLabel label
    decoded := decoded ++ [r.output]
    errs    := errs || r.hasErrors
  return (decoded, errs)

/-- The status codes decoding `labels` raises, in label order without
    duplicates. Companion to `decodeLabels`, which joins the flags. -/
def decodeLabelsStatuses (labels : List (List Nat)) : List Map.Status :=
  (labels.flatMap (fun label => (decodeLabel label).statuses)).eraseDups

/-- Every status the label array raises: the decoding codes, and for a label
    that decoded, the validity codes read off its decoded form.

    A label whose Punycode decoding failed is preserved verbatim, so its own
    `xn--` prefix would otherwise trip the third-and-fourth-hyphen rule and the
    prefix rule. The decoding failure is what the file reports for such a label,
    and the validity checks have no decoded form to read, so they are not
    applied to it. -/
def labelArrayStatuses (opts : Options) (labels : List (List Nat)) : List Map.Status :=
  (labels.flatMap (fun label =>
    let r := decodeLabel label
    if r.statuses.contains Map.Status.P4 then r.statuses
    else
      r.statuses ++ labelStatuses opts r.output
        ++ (if opts.checkJoiners then labelJoinerStatuses r.output else []))).eraseDups

/-- Apply the UTS #46 ToUnicode algorithm under non-transitional
    processing with the given `opts`. The algorithm runs to
    completion — disallowed codepoints, Punycode failures, and
    failed validity checks each contribute to `hasErrors` while
    the output is produced as if the recovery path was taken.
    UTS #46 §4.4's `VerifyDnsLength` flag controls only `A4_1` and
    `A4_2` on the toAscii side. toUnicode's own length concern is the
    empty domain, which `IdnaTestV2.txt` reports as `X4_2`. -/
def toUnicode (input : List Nat) (opts : Options := defaultOptions) :
    Map.Result :=
  let mapped              := Map.mapNonTransitional input
  let normalized          := Unicode.Normalization.NFC.toNFC mapped.output
  let labels              := splitLabels normalized
  let (decoded, decErr)   := decodeLabels labels
  let labelErr            := ! labelsPass opts decoded
  let joined              := joinLabels decoded
  -- An empty domain is invalid per RFC 5891 / UTS #46 — the
  -- domain must have at least one non-empty label.
  let emptyErr            := joined.isEmpty
  { output    := joined
    hasErrors := mapped.hasErrors || decErr || labelErr || emptyErr
    statuses  :=
      -- `X4_2` is toUnicode's label-length code, and a label of length zero
      -- violates it: the file reports it for a domain that is empty and for one
      -- carrying an empty label between two others.
      (mapped.statuses ++ labelArrayStatuses opts labels
        ++ (if opts.checkBidi then domainBidiStatuses decoded else [])
        ++ (if emptyErr || hasNonTrailingEmptyLabel decoded then
              [Map.Status.X4_2] else [])).eraseDups }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 TOASCII  (UTS #46 §4.3)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a valid Unicode scalar — outside the
    UTF-16 surrogate range (U+D800..U+DFFF) and not above the
    Unicode maximum U+10FFFF. Punycode is only defined for
    sequences of valid scalars; codepoints outside this set
    cannot be Punycode-encoded. -/
def isValidScalar (cp : Nat) : Bool :=
  Nat.ble cp 0x10FFFF
    && ! (Nat.ble 0xD800 cp && Nat.ble cp 0xDFFF)

/-- Encode a single label into its ASCII form. Three cases:

      * All-ASCII label → output is the label unchanged,
        hasErrors=false.
      * Label contains a non-scalar codepoint (surrogate or
        beyond U+10FFFF) → Punycode is undefined on the input;
        the output is the original sequence preserved with
        hasErrors=true (UTS #46 §4.3 step 3 / RFC 3492 §3.1).
      * Otherwise → Punycode-encode and prefix with `xn--`. A
        Punycode failure on a valid-scalar input falls back to
        preserving the label with hasErrors=true. -/
def encodeLabel (label : List Nat) : Map.Result :=
  if allAscii label then
    { output := label, hasErrors := false }
  else if ! label.all isValidScalar then
    -- An unpaired surrogate cannot be Punycode-encoded. `IdnaTestV2.txt`
    -- names a Punycode encoding failure `A3`.
    { output := label, hasErrors := true, statuses := [Map.Status.A3] }
  else
    match Punycode.encode label with
    | none     =>
      { output := label, hasErrors := true, statuses := [Map.Status.A3] }
    | some pny =>
      { output := [0x78, 0x6E, 0x2D, 0x2D] ++ stringToCps pny,
        hasErrors := false }

/-- Encode every label in `labels`, joining outputs with U+002E and
    or'ing their `hasErrors` flags. -/
def encodeLabels (labels : List (List Nat)) : Map.Result := Id.run do
  let mut encoded : List (List Nat) := []
  let mut errs    : Bool              := false
  let mut sts     : List Map.Status   := []
  for label in labels do
    let r := encodeLabel label
    encoded := encoded ++ [r.output]
    errs    := errs || r.hasErrors
    sts     := sts ++ r.statuses
  return { output := joinLabels encoded, hasErrors := errs, statuses := sts.eraseDups }

/-- Apply the UTS #46 ToASCII algorithm under non-transitional processing with
    the given `opts`. Errors from the inner `toUnicode`, from per-label Punycode
    encoding, and from the post-encoding length checks are joined into
    `hasErrors`. The two length checks report separately: `A4_1` for the domain
    and `A4_2` for the label, both applied when `verifyDnsLength` is set.

    `X4_2` is dropped from the inherited statuses because it is toUnicode's
    reading of an empty domain; toASCII states the same condition as `A4_1` and
    `A4_2`, which the length check below raises. -/
def toAscii (input : List Nat) (opts : Options := defaultOptions) :
    Map.Result :=
  let unicode  := toUnicode input opts
  let labels   := splitLabels unicode.output
  let enc      := encodeLabels labels
  let encoded  := splitLabels enc.output
  let domainOk := totalLengthOk enc.output
  let labelOk  := labelsLengthOk encoded
  let lenErr   := opts.verifyDnsLength && (! domainOk || ! labelOk)
  { output := enc.output
    hasErrors := unicode.hasErrors || enc.hasErrors || lenErr
    statuses :=
      ((unicode.statuses.filter (fun s => s != Map.Status.X4_2)) ++ enc.statuses
        ++ (if opts.verifyDnsLength && ! domainOk then [Map.Status.A4_1] else [])
        ++ (if opts.verifyDnsLength && ! labelOk then [Map.Status.A4_2] else [])
        ).eraseDups }

/-- Apply the UTS #46 ToASCII algorithm under transitional processing
    with the given `opts`. Transitional processing maps the four
    UTS #46 §2.3 Deviation codepoints (matching IDNA2003 behaviour);
    for a non-deviation input the output equals `toAscii input opts`. -/
def toAsciiTransitional (input : List Nat) (opts : Options := defaultOptions) :
    Map.Result :=
  let mapped              := Map.mapTransitional input
  let normalized          := Unicode.Normalization.NFC.toNFC mapped.output
  let labels              := splitLabels normalized
  let (decoded, decErr)   := decodeLabels labels
  let labelErr            := ! labelsPass opts decoded
  let enc                 := encodeLabels decoded
  let encoded             := splitLabels enc.output
  let domainOk            := totalLengthOk enc.output
  let labelOk             := labelsLengthOk encoded
  let encLenErr           := opts.verifyDnsLength && (! domainOk || ! labelOk)
  { output    := enc.output
    hasErrors := mapped.hasErrors || decErr || labelErr || enc.hasErrors
                  || encLenErr
    statuses  :=
      (mapped.statuses ++ labelArrayStatuses opts labels
        ++ (if opts.checkBidi then domainBidiStatuses decoded else [])
        ++ enc.statuses
        ++ (if opts.verifyDnsLength && ! domainOk then [Map.Status.A4_1] else [])
        ++ (if opts.verifyDnsLength && ! labelOk then [Map.Status.A4_2] else [])
        ).eraseDups }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 SAMPLE DOMAINS
-- ═══════════════════════════════════════════════════════════════════════════════

-- The sample-domain checks reduce the full IDNA pipeline over concrete label
-- lists; the "xn--" vectors drive the Punycode loop, which climbs to the
-- largest non-basic codepoint. Close them with decide +kernel (kernel Nat, no
-- whnf thunk per step) under a raised recursion depth for the List traversal.
set_option maxRecDepth 100000

/-- "example.com" round-trips identically — pure ASCII. -/
theorem toUnicode_example :
    toUnicode (stringToCps "example.com")
      = { output := stringToCps "example.com", hasErrors := false } := by
  decide +kernel

theorem toAscii_example :
    toAscii (stringToCps "example.com")
      = { output := stringToCps "example.com", hasErrors := false } := by
  decide +kernel

/-- "EXAMPLE.COM" → "example.com" via case-folding. -/
theorem toUnicode_EXAMPLE :
    toUnicode (stringToCps "EXAMPLE.COM")
      = { output := stringToCps "example.com", hasErrors := false } := by
  decide +kernel

theorem toAscii_EXAMPLE :
    toAscii (stringToCps "EXAMPLE.COM")
      = { output := stringToCps "example.com", hasErrors := false } := by
  decide +kernel

/-- "fass.de" round-trips identically. -/
theorem toAscii_fass :
    toAscii (stringToCps "fass.de")
      = { output := stringToCps "fass.de", hasErrors := false } := by
  decide +kernel

/-- IdnaTestV2 vector: "faß.de" → "xn--fa-hia.de" non-transitionally
    (sharp s is kept under non-transitional, then Punycode-encoded). -/
theorem toAscii_faß :
    toAscii ([0x0066, 0x0061, 0x00DF, 0x002E, 0x0064, 0x0065])
      = { output := stringToCps "xn--fa-hia.de", hasErrors := false } := by
  decide +kernel

/-- IdnaTestV2 vector: "Faß.de" → "faß.de" under ToUnicode. -/
theorem toUnicode_Faß :
    toUnicode ([0x0046, 0x0061, 0x00DF, 0x002E, 0x0064, 0x0065])
      = { output := [0x0066, 0x0061, 0x00DF, 0x002E, 0x0064, 0x0065],
          hasErrors := false } := by
  decide +kernel

/-- IdnaTestV2 vector: "faß.de" → "fass.de" under transitional ToASCII
    (sharp s is mapped to "ss"). -/
theorem toAsciiTransitional_faß :
    toAsciiTransitional ([0x0066, 0x0061, 0x00DF, 0x002E, 0x0064, 0x0065])
      = { output := stringToCps "fass.de", hasErrors := false } := by
  decide +kernel

/-- A pre-encoded "xn--" label round-trips back to the original
    Unicode codepoints under ToUnicode. -/
theorem toUnicode_xn_traditional_chinese :
    toUnicode (stringToCps "xn--ihqwctvzc91f659drss3x8bo0yb.example")
      = { output := [0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD,
                      0x4E0D, 0x8AAA, 0x4E2D, 0x6587, 0x002E]
                    ++ stringToCps "example",
          hasErrors := false } := by
  decide +kernel

end Unicode.Idna.Process
