>>SOURCE FORMAT FREE
IDENTIFICATION DIVISION.
PROGRAM-ID. USEC.

DATA DIVISION.
WORKING-STORAGE SECTION.
01 CMD-LINE PIC X(20000).
01 OP-NAME PIC X(32).
01 PROFILE-NAME PIC X(32).
01 MODE-NAME PIC X(32).
01 NUM-LIST PIC X(19000).
01 IDX PIC 9(5) COMP-5.
01 JDX PIC 9(5) COMP-5.
01 POS-IDX PIC 9(5) COMP-5.
01 LIST-LEN PIC 9(5) COMP-5.
01 CHAR-1 PIC X.
01 IN-NUM PIC 9 VALUE 0.
01 CUR-NUM PIC 9(9) COMP-5 VALUE 0.
01 CP-COUNT PIC 9(5) COMP-5 VALUE 0.
01 CP-TABLE.
   05 CP OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 OUT-COUNT PIC 9(5) COMP-5 VALUE 0.
01 OUT-TABLE.
   05 OUT-CP OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 FINDING-COUNT PIC 9(4) COMP-5 VALUE 0.
01 FINDING-TABLE.
   05 FINDING-CODE OCCURS 128 TIMES PIC X(128).
   05 FINDING-POS OCCURS 128 TIMES PIC X(256).
01 ACTION-NAME PIC X(16) VALUE "allow".
01 BLOCKING-FLAG PIC 9 VALUE 0.
01 POS-NUM PIC Z(8)9.
01 POS-TEXT PIC X(256).
01 TEMP-CODE PIC X(128).
01 TEMP-SUB PIC X(48).
01 BYTE-1 PIC 9(9) COMP-5.
01 BYTE-2 PIC 9(9) COMP-5.
01 BYTE-3 PIC 9(9) COMP-5.
01 BYTE-4 PIC 9(9) COMP-5.
01 NEED PIC 9 COMP-5.
01 CODEPOINT PIC 9(9) COMP-5.
01 ERR-POS PIC 9(5) COMP-5.
01 ERR-CODE PIC X(128).
01 ENDIAN-FLAG PIC X VALUE "L".
01 UNIT-1 PIC 9(9) COMP-5.
01 UNIT-2 PIC 9(9) COMP-5.
01 EMB-DEPTH PIC 9(5) COMP-5.
01 ISO-DEPTH PIC 9(5) COMP-5.
01 ORPHAN-POS PIC 9(5) COMP-5.
01 MAX-DEPTH PIC 9(5) COMP-5.
01 TAG-COUNT PIC 9(5) COMP-5.
01 VS-COUNT PIC 9(5) COMP-5.
01 ZW-COUNT PIC 9(5) COMP-5.
01 NNBSP-COUNT PIC 9(5) COMP-5.
01 ANNO-COUNT PIC 9(5) COMP-5.
01 WJ-COUNT PIC 9(5) COMP-5.
01 HAS-LATN PIC 9 VALUE 0.
01 HAS-GREK PIC 9 VALUE 0.
01 HAS-CYRL PIC 9 VALUE 0.
01 RTL-RUN PIC 9(5) COMP-5.
01 RTL-BEST PIC 9(5) COMP-5.
01 RTL-BEST-START PIC 9(5) COMP-5.
01 FIRST-RTL PIC 9(5) COMP-5.
01 FOUND-FLAG PIC 9 VALUE 0.
01 HAS-BIDI PIC 9 VALUE 0.
01 HAS-TAG PIC 9 VALUE 0.
01 HAS-BAD-VS PIC 9 VALUE 0.
01 HAS-CONFUSABLE PIC 9 VALUE 0.
01 HAS-OVERRIDE PIC 9 VALUE 0.
01 HAS-ISOLATE PIC 9 VALUE 0.
01 TRAILING-WS PIC 9 VALUE 0.
01 UPPER-FLAG PIC 9 VALUE 0.
01 DOUBLE-WS PIC 9 VALUE 0.
01 UNKNOWN-WORD PIC 9 VALUE 0.
01 WORDLIST-MISMATCH PIC 9 VALUE 0.
01 PREV-WS PIC 9 VALUE 0.
01 WORD-HAS-CHARS PIC 9 VALUE 0.
01 WORD-FIRST-CP PIC 9 VALUE 1.
01 WORD-PTR PIC 9(5) COMP-5.
01 WORD-KEY PIC X(1024).
01 LOOKUP-CP PIC 9(9) COMP-5.
01 PAIR-BASE PIC 9(9) COMP-5.
01 PAIR-VS PIC 9(9) COMP-5.
01 TABLE-FLAG PIC 9 VALUE 0.
01 GCB-CLASS PIC 9(2) COMP-5 VALUE 0.
01 INCB-CLASS PIC 9(2) COMP-5 VALUE 0.
01 IS-EP-FLAG PIC 9 COMP-5 VALUE 0.
01 BC-CLASS PIC 9(2) COMP-5 VALUE 0.
01 PC-CLASS PIC 9(2) COMP-5 VALUE 0.
01 CUR-INCB PIC 9(2) COMP-5 VALUE 0.
01 HAS-PREV PIC 9 COMP-5 VALUE 0.
01 EPIC-STATE PIC 9 COMP-5 VALUE 0.
01 INCB-STATE PIC 9 COMP-5 VALUE 0.
01 NEW-EPIC PIC 9 COMP-5 VALUE 0.
01 NEW-INCB PIC 9 COMP-5 VALUE 0.
01 RI-RUN PIC 9(9) COMP-5 VALUE 0.
01 BREAK-FLAG PIC 9 COMP-5 VALUE 0.
01 OFFSET-VAL PIC 9(9) COMP-5 VALUE 0.
01 BOUND-COUNT PIC 9(9) COMP-5 VALUE 0.
01 CLUSTER-COUNT PIC 9(9) COMP-5 VALUE 0.
01 BOUND-TEXT PIC X(20000).
01 COUNT-TEXT PIC Z(8)9.
01 VALID-TEXT PIC X(8).
*> ── hash-input-stability (K2) context args + NFC scratch ──────────────
01 ENC-ARG PIC X(64).
01 RFC-ARG PIC X(48).
01 AUDIT-ARG PIC X(4096).
01 WEBHOOK-ARG PIC X(4096).
01 RFC-TAG PIC X(48).
01 ENC-UPPER PIC X(64).
01 ENC-ACTIVE PIC 9 VALUE 0.
01 RFC-ACTIVE PIC 9 VALUE 0.
01 AUDIT-ACTIVE PIC 9 VALUE 0.
01 WEBHOOK-ACTIVE PIC 9 VALUE 0.
01 HIS-DONE PIC 9 VALUE 0.
01 HIS-POS PIC 9(9) COMP-5 VALUE 0.
01 TRAIL-COUNT PIC 9(5) COMP-5 VALUE 0.
01 CUR-CP PIC 9(9) COMP-5.
01 CUR-CCC PIC 9(4) COMP-5.
01 LAST-CCC PIC S9(4) COMP-5.
01 STARTER-IDX PIC 9(5) COMP-5.
01 DID-COMPOSE PIC 9 VALUE 0.
01 CCC-VAL PIC 9(4) COMP-5 VALUE 0.
01 DEC-FOUND PIC 9 VALUE 0.
01 DEC-LEN PIC 9(2) COMP-5 VALUE 0.
01 DEC-TABLE.
   05 DEC-CP OCCURS 20 TIMES PIC 9(9) COMP-5.
01 COMP-A PIC 9(9) COMP-5.
01 COMP-B PIC 9(9) COMP-5.
01 COMP-RESULT PIC 9(9) COMP-5.
01 COMP-FOUND PIC 9 VALUE 0.
01 HS-INDEX PIC 9(9) COMP-5.
01 HL-VAL PIC 9(9) COMP-5.
01 HV-VAL PIC 9(9) COMP-5.
01 HT-INDEX PIC 9(9) COMP-5.
01 NFD-COUNT PIC 9(5) COMP-5 VALUE 0.
01 NFD-TABLE.
   05 NFD-CP OCCURS 16384 TIMES PIC 9(9) COMP-5.
01 NFC-COUNT PIC 9(5) COMP-5 VALUE 0.
01 NFC-TABLE.
   05 NFC-CP OCCURS 16384 TIMES PIC 9(9) COMP-5.
01 AW-COUNT PIC 9(5) COMP-5 VALUE 0.
01 AW-TABLE.
   05 AW-CP OCCURS 1024 TIMES PIC 9(9) COMP-5.
01 SV-COUNT PIC 9(5) COMP-5 VALUE 0.
01 SV-TABLE.
   05 SV-CP OCCURS 1024 TIMES PIC 9(9) COMP-5.
01 A-COUNT PIC 9(5) COMP-5 VALUE 0.
01 A-TABLE.
   05 A-CP OCCURS 16384 TIMES PIC 9(9) COMP-5.
01 B-COUNT PIC 9(5) COMP-5 VALUE 0.
01 B-TABLE.
   05 B-CP OCCURS 16384 TIMES PIC 9(9) COMP-5.
01 DIV-FOUND PIC 9 VALUE 0.
01 DIV-POS PIC 9(9) COMP-5 VALUE 0.
01 COMMON-LEN PIC 9(5) COMP-5 VALUE 0.
01 SIDE-SRC PIC X(4096).
01 SIDE-LEN PIC 9(5) COMP-5.
01 SIDE-COUNT PIC 9(5) COMP-5 VALUE 0.
01 SIDE-TABLE.
   05 SIDE-CP OCCURS 1024 TIMES PIC 9(9) COMP-5.
01 RUN-LO PIC 9(5) COMP-5.
01 RUN-HI PIC 9(5) COMP-5.
01 KDX PIC 9(5) COMP-5.
01 MDX PIC 9(5) COMP-5.
01 PDX PIC 9(5) COMP-5.
01 KEY-CP PIC 9(9) COMP-5.
01 KEY-CCC PIC 9(4) COMP-5.
01 SORT-STOP PIC 9 VALUE 0.
*> ── stream-safe-violation (F) non-starter run scan ────────────────────
01 SS-LIMIT PIC 9(5) COMP-5 VALUE 30.
01 SS-IN-RUN PIC 9 VALUE 0.
01 SS-RUN-START PIC 9(5) COMP-5 VALUE 0.
01 SS-RUN-LEN PIC 9(5) COMP-5 VALUE 0.
01 SS-BASE-POS PIC 9(9) COMP-5 VALUE 0.
01 SS-FIRED PIC 9 VALUE 0.
*> ── ai-watermark-detectability (K) marker tables + context ────────────
01 IS-EMOJI-FLAG PIC 9 COMP-5 VALUE 0.
01 IS-SKIN-BASE-FLAG PIC 9 COMP-5 VALUE 0.
01 IS-EMOJI-PRES-FLAG PIC 9 COMP-5 VALUE 0.
01 AW-ZWSP-TOL PIC 9(5) COMP-5 VALUE 0.
01 AW-ADV-TOL PIC 9(5) COMP-5 VALUE 0.
01 AWD-DONE PIC 9 VALUE 0.
01 AWD-ARITH-OK PIC 9 VALUE 0.
01 AWD-HAS-STRAIGHT PIC 9 VALUE 0.
01 AWD-HAS-HYPHEN PIC 9 VALUE 0.
01 AWD-PREV-EMOJI PIC 9 VALUE 0.
01 AWD-NEXT-EMOJI PIC 9 VALUE 0.
01 AWD-IS-VS PIC 9 VALUE 0.
01 AWD-IS-ZWJ PIC 9 VALUE 0.
01 AWD-IS-DI PIC 9 VALUE 0.
01 AWD-VOCAB-FOUND PIC 9 VALUE 0.
01 AWD-VOCAB-POS PIC 9(9) COMP-5 VALUE 0.
01 AWD-CATEGORY PIC 9(5) COMP-5 VALUE 0.
01 AWD-TOTAL PIC 9(9) COMP-5 VALUE 0.
01 AWD-FIRST-GAP PIC 9(9) COMP-5 VALUE 0.
01 AWD-GAP PIC 9(9) COMP-5 VALUE 0.
01 AWD-MATCH PIC 9 VALUE 0.
01 AWD-ALLEQ PIC 9 VALUE 0.
01 AWD-MAX-START PIC 9(9) COMP-5 VALUE 0.
01 AWD-BYTE PIC 9(9) COMP-5 VALUE 0.
01 VDX PIC 9(5) COMP-5.
01 SDX PIC 9(9) COMP-5.
01 PAT-LEN PIC 9(2) COMP-5.
01 AWD-NNBSP-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-NNBSP-TABLE.
   05 AWD-NNBSP OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 AWD-ZWSP-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-ZWSP-TABLE.
   05 AWD-ZWSP OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 AWD-VS-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-VS-TABLE.
   05 AWD-VS OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 AWD-ZWJ-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-ZWJ-TABLE.
   05 AWD-ZWJ OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 AWD-CURLY-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-CURLY-TABLE.
   05 AWD-CURLY OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 AWD-EMDASH-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-EMDASH-TABLE.
   05 AWD-EMDASH OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 AWD-DI-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-DI-TABLE.
   05 AWD-DI OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 AWD-INVIS-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-INVIS-TABLE.
   05 AWD-INVIS OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 AWD-SEL-N PIC 9(5) COMP-5 VALUE 0.
01 AWD-SEL-TABLE.
   05 AWD-SEL OCCURS 4096 TIMES PIC 9(9) COMP-5.
*> ── emoji-zwj-integrity (I3) ZWJ-sequence scan state ──────────────────
01 EZ-ZWJ-N PIC 9(5) COMP-5 VALUE 0.
01 EZ-ZWJ-TABLE.
   05 EZ-ZWJ OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 EZ-SKIN-N PIC 9(5) COMP-5 VALUE 0.
01 EZ-IS-RGI PIC 9 VALUE 0.
01 EZ-DONE PIC 9 VALUE 0.
01 EZ-INJ-FOUND PIC 9 VALUE 0.
01 EZ-INJ-POS PIC 9(9) COMP-5 VALUE 0.
01 EZ-PREV-TARGET PIC 9 VALUE 0.
01 EZ-NEXT-TARGET PIC 9 VALUE 0.
01 EZ-POS-N PIC 9(5) COMP-5 VALUE 0.
01 EZ-POS-TABLE.
   05 EZ-POS OCCURS 4096 TIMES PIC 9(9) COMP-5.
01 SEQ-KEY PIC X(256).
*> ── renderer-divergence (D) display-variance ladder state ─────────────
*> MIN-COMBINING-STACK and ZWJ mirror the Rust reference constants.
01 RD-MIN-STACK PIC 9(2) COMP-5 VALUE 4.
01 RD-ZWJ PIC 9(9) COMP-5 VALUE 8205.
01 RD-DONE PIC 9 VALUE 0.
01 RD-HAS-ZWJ PIC 9 VALUE 0.
01 RD-LTR-COUNT PIC 9(5) COMP-5 VALUE 0.
01 RD-RTL-COUNT PIC 9(5) COMP-5 VALUE 0.
01 RD-ALL-EXT PIC 9 VALUE 0.
01 RD-POS PIC 9(9) COMP-5 VALUE 0.
*> ── filename-disguise (D) extension-disguise ladder state ─────────────
*> The priority-ordered classification (0 clear, 1 RloFlip, 2 WidthClassExt,
*> 3 CombiningInExt, 4 MultipleExtensions), the dot tally, the last-dot index,
*> and the extension-region start. FD-MIN-DOTS mirrors the reference's
*> three-extension advisory bound.
01 FD-MIN-DOTS PIC 9(2) COMP-5 VALUE 3.
01 FD-CLASS PIC 9 VALUE 0.
01 FD-DONE PIC 9 VALUE 0.
01 FD-DOT-COUNT PIC 9(5) COMP-5 VALUE 0.
01 FD-LAST-DOT PIC 9(9) COMP-5 VALUE 0.
01 FD-EXT-START PIC 9(9) COMP-5 VALUE 0.
01 FD-POS PIC 9(9) COMP-5 VALUE 0.
*> ── identifier-form-drift (X) status-shift scan state ─────────────────
*> The sole sub-threat is IdentifierStatusShift (IFD-CLASS 1). IFD-IDX is a
*> dedicated outer index so the per-codepoint NFKD-head reorder — which reuses
*> the shared REORDER-NFD scratch (IDX/JDX/KDX/...) — never clobbers the scan
*> loop. IFD-CP-ALLOWED / IFD-HEAD-ALLOWED are the Identifier_Status of the
*> input codepoint and of its NFKD head; a shift is any position where they
*> differ. IFD-POS is the first such position, 0-indexed.
01 IFD-CLASS PIC 9 VALUE 0.
01 IFD-DONE PIC 9 VALUE 0.
01 IFD-POS PIC 9(9) COMP-5 VALUE 0.
01 IFD-SHIFT-COUNT PIC 9(5) COMP-5 VALUE 0.
01 IFD-IDX PIC 9(5) COMP-5 VALUE 0.
01 IFD-CUR-CP PIC 9(9) COMP-5 VALUE 0.
01 IFD-CP-ALLOWED PIC 9 VALUE 0.
01 IFD-HEAD-ALLOWED PIC 9 VALUE 0.
*> ── width-class-confusion (F) East Asian Width fold state ─────────────
*> UAX #11: a Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint whose NFKD
*> head carries a different width class is a compatibility-fold homograph —
*> ＡＤＭＩＮ folding to ADMIN past an ASCII whitelist. The detector needs only
*> membership, not the full class: an F codepoint folds exactly when its head
*> is not F. WCC-CLASS 1 is FullwidthFold, 2 is HalfwidthFold; Fullwidth takes
*> priority. WCC-POS is the fold position, 0-indexed.
01 WCC-CLASS PIC 9 VALUE 0.
01 WCC-POS PIC 9(9) COMP-5 VALUE 0.
01 WCC-IDX PIC 9(5) COMP-5 VALUE 0.
01 WCC-CUR-CP PIC 9(9) COMP-5 VALUE 0.
01 WCC-CP-WIDE PIC 9 VALUE 0.
01 WCC-HEAD-WIDE PIC 9 VALUE 0.
01 WCC-FULL-POS PIC 9(9) COMP-5 VALUE 0.
01 WCC-FULL-DONE PIC 9 VALUE 0.
01 WCC-HALF-POS PIC 9(9) COMP-5 VALUE 0.
01 WCC-HALF-DONE PIC 9 VALUE 0.
*> ── admissibility-form-drift (X) whole-string admissibility scan state ─
*> The sole sub-threat is AdmissibilityFormDrift (AFD-CLASS 1): the UAX #31
*> whole-string default-identifier ∧ UTS #39 Allowed predicate evaluated on
*> the input differs from the same predicate on its NFKC form. AFD-CP holds
*> whichever sequence the predicate is currently ranging over (the input, or
*> the NFKC form built into NFC-CP); AFD-SEQ-COUNT is its length. AFD-IN-OK
*> and AFD-NFKC-OK are the two admissibility verdicts; a drift is any input on
*> which they disagree. No position is reported — the predicate is whole-string.
01 AFD-SEQ-COUNT PIC 9(5) COMP-5 VALUE 0.
01 AFD-SEQ-TABLE.
   05 AFD-CP OCCURS 16384 TIMES PIC 9(9) COMP-5.
01 AFD-IDX PIC 9(5) COMP-5 VALUE 0.
01 AFD-IN-OK PIC 9 VALUE 0.
01 AFD-NFKC-OK PIC 9 VALUE 0.
01 AFD-ID-RESULT PIC 9 VALUE 0.
01 AFD-DEFAULT-ID PIC 9 VALUE 0.
01 AFD-ALL-ALLOWED PIC 9 VALUE 0.
01 AFD-START-OK PIC 9 VALUE 0.
01 AFD-CONTINUE-OK PIC 9 VALUE 0.
01 AFD-CLASS PIC 9 VALUE 0.
*> ── source-display-divergence (D) aggregator state ───────────────────
*> The aggregator runs the five constituent display/identity detectors over
*> the same codepoint stream and counts how many produced a finding.
*> SDD-FIRED-COUNT is that count; SDD-TAG holds the resolved sub-threat tag —
*> SPACES for clear, the single family tag for exactly one fire, or "Compound"
*> for two or more. No position is reported at this layer (the per-family
*> verdicts carry them), matching the verified reference.
01 SDD-FIRED-COUNT PIC 9(4) COMP-5 VALUE 0.
*> The aggregate runs the constituent detectors and reads FINDING-COUNT to see
*> which fired. The detectors append at FINDING-COUNT + 1, so the count is saved
*> on entry and each constituent's findings land past it and are truncated back,
*> leaving the caller's own findings untouched. Zeroing the count instead would
*> make the constituents overwrite them in place.
01 SDD-SAVED-COUNT PIC 9(4) COMP-5 VALUE 0.
01 SDD-BIDI-PRESENT PIC 9 VALUE 0.

*> Scratch for the form-layer detectors. ONE-POS carries the single implicated
*> index for findings that localise one position, matching the reference, which
*> reports the first divergence rather than the whole span.
01 ONE-POS PIC 9(9) COMP-5 VALUE 0.
*> locale-case-inversion: the locale under test, the 0-based divergence index
*> (LCI-FOUND = 0 when none), and the default-locale lowercase mapping held for
*> comparison against the locale-specific one.
01 LCI-LOCALE PIC 9 VALUE 0.
01 LCI-FOUND PIC 9 VALUE 0.
01 LCI-POS PIC 9(9) COMP-5 VALUE 0.
01 LCI-DEF-LEN PIC 9(4) COMP-5 VALUE 0.
01 LCI-DEF-TAB.
   05 LCI-DEF-CP PIC 9(9) COMP-5 OCCURS 3 TIMES.
01 LCI-CMP-IDX PIC 9(4) COMP-5 VALUE 0.
01 LCI-DIFF PIC 9 VALUE 0.
*> nfc-idempotence-witness: the first index at which the input differs from its
*> normalized form, or 0 when it does not.
01 NFCW-FOUND PIC 9 VALUE 0.
01 NFCW-POS PIC 9(9) COMP-5 VALUE 0.
01 NFCW-COMMON PIC 9(4) COMP-5 VALUE 0.
*> normalization-bomb: per-codepoint compatibility expansion length and the
*> whole-sequence expansion ratios, in hundredths.
01 NB-EXPAND PIC 9(9) COMP-5 VALUE 0.
01 NB-RATIO PIC 9(9) COMP-5 VALUE 0.
01 NB-FOUND PIC 9 VALUE 0.
01 SDD-TAG PIC X(20) VALUE SPACES.
*> ── skin-tone-variation-forgery (I) modifier/VS-abuse ladder state ────
*> The priority-ordered classification (0 clear, 1 StackedSkinTones,
*> 2 InvalidSkinToneTarget, 3 ForcedTextStyle), the base position of the
*> firing pair (0-indexed), and the single implicated position for the two
*> single-position sub-threats. STV-MOD1/STV-MOD2 hold the two stacked
*> skin-tone modifiers so the multi-position emit reports [base+1, base+2].
01 STV-CLASS PIC 9 VALUE 0.
01 STV-DONE PIC 9 VALUE 0.
01 STV-BASE-POS PIC 9(9) COMP-5 VALUE 0.
01 STV-POS PIC 9(9) COMP-5 VALUE 0.
01 STV-MOD1 PIC 9(9) COMP-5 VALUE 0.
01 STV-MOD2 PIC 9(9) COMP-5 VALUE 0.
*> ── UAX #21 full case mapping (used by case-expansion-mismatch) ───────
*> The port's own context-sensitive upper_codepoint / lower_codepoint, mirroring
*> the verified Rust reference ucd casing. SC-LOCALE is the locale discriminant
*> (0 Default, 1 tr, 2 az, 3 lt). find_special_row fills SC-UPPER / SC-LOWER (up
*> to three codepoints each) and SC-FOUND from the generated SpecialCasing rows;
*> SC-SIMPLE-UP / SC-SIMPLE-LO carry the simple mappings used when no row matches.
*> SC-CASED / SC-SOFT-DOTTED are the membership sets the context predicates read.
*> SC-FINAL-SIGMA .. SC-BEFORE-DOT are the five UAX #21 context flags, computed
*> per position from the surrounding text; SC-HAS-CASED-BEFORE / -AFTER are the
*> Final_Sigma sub-terms; SC-SCAN-* drive the prefix/suffix walks.
01 SC-LOCALE PIC 9 VALUE 0.
01 SC-FOUND PIC 9 VALUE 0.
01 SC-UPPER-LEN PIC 9 VALUE 0.
01 SC-UPPER-SEQ.
   05 SC-UPPER PIC 9(9) COMP-5 OCCURS 3 TIMES.
01 SC-LOWER-LEN PIC 9 VALUE 0.
01 SC-LOWER-SEQ.
   05 SC-LOWER PIC 9(9) COMP-5 OCCURS 3 TIMES.
01 SC-SIMPLE-UP PIC 9(9) COMP-5 VALUE 0.
01 SC-SIMPLE-LO PIC 9(9) COMP-5 VALUE 0.
01 SC-CASED PIC 9 VALUE 0.
01 SC-SOFT-DOTTED PIC 9 VALUE 0.
01 SC-FINAL-SIGMA PIC 9 VALUE 0.
01 SC-AFTER-SOFT-DOTTED PIC 9 VALUE 0.
01 SC-AFTER-I PIC 9 VALUE 0.
01 SC-MORE-ABOVE PIC 9 VALUE 0.
01 SC-BEFORE-DOT PIC 9 VALUE 0.
01 SC-HAS-CASED-BEFORE PIC 9 VALUE 0.
01 SC-HAS-CASED-AFTER PIC 9 VALUE 0.
01 SC-SCAN-STOP PIC 9 VALUE 0.
01 SC-SCAN-IDX PIC S9(9) COMP-5 VALUE 0.
01 SC-COPY-IDX PIC 9 VALUE 0.
*> upper_codepoint / lower_codepoint results at a position: the real mapped
*> sequence UC-CP(1..UC-LEN) / LC-CP(1..LC-LEN) whose length the detector reads.
01 UC-LEN PIC 9 VALUE 0.
01 UC-SEQ.
   05 UC-CP PIC 9(9) COMP-5 OCCURS 3 TIMES.
01 LC-LEN PIC 9 VALUE 0.
01 LC-SEQ.
   05 LC-CP PIC 9(9) COMP-5 OCCURS 3 TIMES.
*> ── case-expansion-mismatch (F) classification state ──────────────────
*> The priority-ordered classification (0 clear, 1 UpperExpansion, 2
*> LowerExpansion), the 0-indexed base positions of the first uppercase and first
*> lowercase expansion, the total expansion counts per direction, and the maximum
*> mapped length across the input — the projection of the reference Verdict
*> (input, classify, upper/lower expansion counts, max expansion length).
01 CE-CLASS PIC 9 VALUE 0.
01 CE-UPPER-FOUND PIC 9 VALUE 0.
01 CE-LOWER-FOUND PIC 9 VALUE 0.
01 CE-UPPER-POS PIC 9(9) COMP-5 VALUE 0.
01 CE-LOWER-POS PIC 9(9) COMP-5 VALUE 0.
01 CE-POS PIC 9(9) COMP-5 VALUE 0.
01 CE-UPPER-COUNT PIC 9(5) COMP-5 VALUE 0.
01 CE-LOWER-COUNT PIC 9(5) COMP-5 VALUE 0.
01 CE-MAX-LEN PIC 9(4) COMP-5 VALUE 0.
01 CE-IDX PIC 9(5) COMP-5 VALUE 0.
01 VOCAB-RAW.
   05 FILLER PIC X(26) VALUE "05delve                   ".
   05 FILLER PIC X(26) VALUE "07delving                 ".
   05 FILLER PIC X(26) VALUE "08tapestry                ".
   05 FILLER PIC X(26) VALUE "09intricate               ".
   05 FILLER PIC X(26) VALUE "07nuanced                 ".
   05 FILLER PIC X(26) VALUE "08moreover                ".
   05 FILLER PIC X(26) VALUE "11furthermore             ".
   05 FILLER PIC X(26) VALUE "05realm                   ".
   05 FILLER PIC X(26) VALUE "09elucidate               ".
   05 FILLER PIC X(26) VALUE "10showcasing              ".
   05 FILLER PIC X(26) VALUE "11underscores             ".
   05 FILLER PIC X(26) VALUE "11underscored             ".
   05 FILLER PIC X(26) VALUE "07pivotal                 ".
   05 FILLER PIC X(26) VALUE "07bolster                 ".
   05 FILLER PIC X(26) VALUE "12multifaceted            ".
   05 FILLER PIC X(26) VALUE "09testament               ".
   05 FILLER PIC X(26) VALUE "06foster                  ".
   05 FILLER PIC X(26) VALUE "08holistic                ".
   05 FILLER PIC X(26) VALUE "08paradigm                ".
   05 FILLER PIC X(26) VALUE "14transformative          ".
   05 FILLER PIC X(26) VALUE "09spearhead               ".
   05 FILLER PIC X(26) VALUE "10meticulous              ".
   05 FILLER PIC X(26) VALUE "12meticulously            ".
   05 FILLER PIC X(26) VALUE "07empower                 ".
   05 FILLER PIC X(26) VALUE "10empowering              ".
   05 FILLER PIC X(26) VALUE "08profound                ".
   05 FILLER PIC X(26) VALUE "10profoundly              ".
   05 FILLER PIC X(26) VALUE "10compelling              ".
   05 FILLER PIC X(26) VALUE "13comprehensive           ".
   05 FILLER PIC X(26) VALUE "07crucial                 ".
   05 FILLER PIC X(26) VALUE "08daunting                ".
   05 FILLER PIC X(26) VALUE "06robust                  ".
   05 FILLER PIC X(26) VALUE "10streamline              ".
   05 FILLER PIC X(26) VALUE "06enrich                  ".
   05 FILLER PIC X(26) VALUE "09exemplify               ".
   05 FILLER PIC X(26) VALUE "11captivating             ".
   05 FILLER PIC X(26) VALUE "10discerning              ".
   05 FILLER PIC X(26) VALUE "09mesmerize               ".
   05 FILLER PIC X(26) VALUE "11intricately             ".
   05 FILLER PIC X(26) VALUE "05imbue                   ".
   05 FILLER PIC X(26) VALUE "20plays a crucial role    ".
   05 FILLER PIC X(26) VALUE "20plays a pivotal role    ".
   05 FILLER PIC X(26) VALUE "23it is important to note ".
   05 FILLER PIC X(26) VALUE "18it is worth noting      ".
   05 FILLER PIC X(26) VALUE "13in conclusion           ".
   05 FILLER PIC X(26) VALUE "10in essence              ".
   05 FILLER PIC X(26) VALUE "10delve into              ".
   05 FILLER PIC X(26) VALUE "12delving into            ".
   05 FILLER PIC X(26) VALUE "11tapestry of             ".
   05 FILLER PIC X(26) VALUE "08realm of                ".
01 VOCAB-TABLE REDEFINES VOCAB-RAW.
   05 VOCAB-ENTRY OCCURS 50 TIMES.
      10 VOCAB-LEN PIC 9(2).
      10 VOCAB-CHARS PIC X(24).

PROCEDURE DIVISION.
MAIN.
    ACCEPT CMD-LINE FROM COMMAND-LINE
    UNSTRING CMD-LINE DELIMITED BY ALL SPACE
        INTO OP-NAME PROFILE-NAME MODE-NAME NUM-LIST
             ENC-ARG RFC-ARG AUDIT-ARG WEBHOOK-ARG
    END-UNSTRING
    PERFORM PARSE-NUMBERS
    IF OP-NAME = "is-utf8-blob" OR OP-NAME = "validate-utf8"
        PERFORM DECODE-UTF8
        PERFORM EMIT-BLOB
        STOP RUN
    END-IF
    IF OP-NAME = "grapheme"
        PERFORM PROCESS-GRAPHEME
        PERFORM EMIT-GRAPHEME
        STOP RUN
    END-IF
    IF OP-NAME = "scan-utf8"
        PERFORM DECODE-UTF8
        IF FINDING-COUNT = 0
            PERFORM SCAN-CORE
        END-IF
    ELSE
        IF OP-NAME = "scan-utf16le" OR OP-NAME = "scan-utf16be"
            IF OP-NAME = "scan-utf16be"
                MOVE "B" TO ENDIAN-FLAG
            ELSE
                MOVE "L" TO ENDIAN-FLAG
            END-IF
            PERFORM DECODE-UTF16
            IF FINDING-COUNT = 0
                PERFORM SCAN-CORE
            END-IF
        ELSE
            IF OP-NAME = "scan-utf32le" OR OP-NAME = "scan-utf32be"
                IF OP-NAME = "scan-utf32be"
                    MOVE "B" TO ENDIAN-FLAG
                ELSE
                    MOVE "L" TO ENDIAN-FLAG
                END-IF
                PERFORM DECODE-UTF32
                IF FINDING-COUNT = 0
                    PERFORM SCAN-CORE
                END-IF
            ELSE
                PERFORM COPY-INPUT-TO-OUTPUT
                IF OP-NAME = "forms"
                    PERFORM SCAN-FORMS
                ELSE
                    IF OP-NAME = "bip39"
                        PERFORM SCAN-BIP39
                    ELSE
                        IF OP-NAME = "hash-input-stability"
                            PERFORM SCAN-HASH-INPUT-STABILITY
                        ELSE
                            IF OP-NAME = "ai-watermark-detectability"
                                PERFORM SCAN-AI-WATERMARK
                            ELSE
                                IF OP-NAME = "stream-safe-violation"
                                    PERFORM SCAN-STREAM-SAFE
                                ELSE
                                    IF OP-NAME = "emoji-zwj-integrity"
                                        PERFORM SCAN-EMOJI-ZWJ
                                    ELSE
                                        IF OP-NAME = "renderer-divergence"
                                            PERFORM SCAN-RENDERER-DIVERGENCE
                                        ELSE
                                            IF OP-NAME = "filename-disguise"
                                                PERFORM SCAN-FILENAME-DISGUISE
                                            ELSE
                                                IF OP-NAME = "identifier-form-drift"
                                                    PERFORM SCAN-IDENTIFIER-FORM-DRIFT
                                                ELSE
                                                    IF OP-NAME = "skin-tone-variation-forgery"
                                                        PERFORM SCAN-SKIN-TONE-VARIATION-FORGERY
                                                    ELSE
                                                        IF OP-NAME = "case-expansion-mismatch"
                                                            PERFORM SCAN-CASE-EXPANSION-MISMATCH
                                                        ELSE
                                                            IF OP-NAME = "admissibility-form-drift"
                                                                PERFORM SCAN-ADMISSIBILITY-FORM-DRIFT
                                                            ELSE
                                                                IF OP-NAME = "source-display-divergence"
                                                                    PERFORM SCAN-SOURCE-DISPLAY-DIVERGENCE
                                                                ELSE
                                                                    IF OP-NAME = "width-class-confusion"
                                                                        PERFORM SCAN-WIDTH-CLASS-CONFUSION
                                                                    ELSE
                                                                        PERFORM SCAN-CORE
                                                                    END-IF
                                                                END-IF
                                                            END-IF
                                                        END-IF
                                                    END-IF
                                                END-IF
                                            END-IF
                                        END-IF
                                    END-IF
                                END-IF
                            END-IF
                        END-IF
                    END-IF
                END-IF
            END-IF
        END-IF
    END-IF
    PERFORM SELECT-ACTION
    PERFORM EMIT-RESULT
    STOP RUN.

PARSE-NUMBERS.
    MOVE 0 TO CP-COUNT CUR-NUM IN-NUM
    MOVE FUNCTION LENGTH(FUNCTION TRIM(NUM-LIST)) TO LIST-LEN
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > LIST-LEN
        MOVE NUM-LIST(IDX:1) TO CHAR-1
        IF CHAR-1 >= "0" AND CHAR-1 <= "9"
            COMPUTE CUR-NUM = (CUR-NUM * 10) + FUNCTION NUMVAL(CHAR-1)
            MOVE 1 TO IN-NUM
        ELSE
            IF IN-NUM = 1
                ADD 1 TO CP-COUNT
                MOVE CUR-NUM TO CP(CP-COUNT)
                MOVE 0 TO CUR-NUM IN-NUM
            END-IF
        END-IF
    END-PERFORM
    IF IN-NUM = 1
        ADD 1 TO CP-COUNT
        MOVE CUR-NUM TO CP(CP-COUNT)
    END-IF.

COPY-INPUT-TO-OUTPUT.
    MOVE CP-COUNT TO OUT-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO OUT-CP(IDX)
    END-PERFORM.

DECODE-UTF8.
    MOVE 0 TO OUT-COUNT
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR FINDING-COUNT > 0
        MOVE CP(IDX) TO BYTE-1
        IF BYTE-1 < 128
            ADD 1 TO OUT-COUNT
            MOVE BYTE-1 TO OUT-CP(OUT-COUNT)
            ADD 1 TO IDX
        ELSE
            IF BYTE-1 < 194
                COMPUTE ERR-POS = IDX - 1
                MOVE "unicode.security.C.malformed-utf8.InvalidStartByte" TO ERR-CODE
                PERFORM ADD-ERR-FINDING
                ADD 1 TO IDX
            ELSE
                IF BYTE-1 < 224
                    MOVE 2 TO NEED
                    PERFORM DECODE-MULTIBYTE
                ELSE
                    IF BYTE-1 < 240
                        MOVE 3 TO NEED
                        PERFORM DECODE-MULTIBYTE
                    ELSE
                        IF BYTE-1 < 245
                            MOVE 4 TO NEED
                            PERFORM DECODE-MULTIBYTE
                        ELSE
                            COMPUTE ERR-POS = IDX - 1
                            MOVE "unicode.security.C.malformed-utf8.InvalidStartByte" TO ERR-CODE
                            PERFORM ADD-ERR-FINDING
                            ADD 1 TO IDX
                        END-IF
                    END-IF
                END-IF
            END-IF
        END-IF
    END-PERFORM.

DECODE-MULTIBYTE.
    IF IDX + NEED - 1 > CP-COUNT
        MOVE CP-COUNT TO ERR-POS
        MOVE "unicode.security.C.malformed-utf8.TruncatedSequence" TO ERR-CODE
        PERFORM ADD-ERR-FINDING
        MOVE CP-COUNT TO IDX
    ELSE
        MOVE CP(IDX + 1) TO BYTE-2
        IF BYTE-2 < 128 OR BYTE-2 > 191
            MOVE IDX TO ERR-POS
            MOVE "unicode.security.C.malformed-utf8.InvalidContinuationByte" TO ERR-CODE
            PERFORM ADD-ERR-FINDING
        ELSE
            IF NEED = 2
                COMPUTE CODEPOINT = ((BYTE-1 - 192) * 64) + (BYTE-2 - 128)
            ELSE
                MOVE CP(IDX + 2) TO BYTE-3
                IF BYTE-3 < 128 OR BYTE-3 > 191
                    COMPUTE ERR-POS = IDX + 1
                    MOVE "unicode.security.C.malformed-utf8.InvalidContinuationByte" TO ERR-CODE
                    PERFORM ADD-ERR-FINDING
                ELSE
                    IF NEED = 3
                        COMPUTE CODEPOINT = ((BYTE-1 - 224) * 4096) + ((BYTE-2 - 128) * 64) + (BYTE-3 - 128)
                    ELSE
                        MOVE CP(IDX + 3) TO BYTE-4
                        IF BYTE-4 < 128 OR BYTE-4 > 191
                            COMPUTE ERR-POS = IDX + 2
                            MOVE "unicode.security.C.malformed-utf8.InvalidContinuationByte" TO ERR-CODE
                            PERFORM ADD-ERR-FINDING
                        ELSE
                            COMPUTE CODEPOINT = ((BYTE-1 - 240) * 262144) + ((BYTE-2 - 128) * 4096) + ((BYTE-3 - 128) * 64) + (BYTE-4 - 128)
                        END-IF
                    END-IF
                END-IF
            END-IF
            IF FINDING-COUNT = 0
                IF (NEED = 2 AND CODEPOINT < 128) OR (NEED = 3 AND CODEPOINT < 2048) OR (NEED = 4 AND CODEPOINT < 65536)
                    COMPUTE ERR-POS = IDX - 1
                    MOVE "unicode.security.C.malformed-utf8.OverlongEncoding" TO ERR-CODE
                    PERFORM ADD-ERR-FINDING
                ELSE
                    IF CODEPOINT >= 55296 AND CODEPOINT <= 57343
                        COMPUTE ERR-POS = IDX + NEED - 2
                        MOVE "unicode.security.C.malformed-utf8.SurrogateCodepoint" TO ERR-CODE
                        PERFORM ADD-ERR-FINDING
                    ELSE
                        IF CODEPOINT > 1114111
                            COMPUTE ERR-POS = IDX + NEED - 2
                            MOVE "unicode.security.C.malformed-utf8.CodepointBeyondMax" TO ERR-CODE
                            PERFORM ADD-ERR-FINDING
                        ELSE
                            ADD 1 TO OUT-COUNT
                            MOVE CODEPOINT TO OUT-CP(OUT-COUNT)
                            ADD NEED TO IDX
                        END-IF
                    END-IF
                END-IF
            END-IF
        END-IF
    END-IF.

ADD-ERR-FINDING.
    MOVE ERR-POS TO POS-NUM
    MOVE FUNCTION TRIM(POS-NUM) TO POS-TEXT
    ADD 1 TO FINDING-COUNT
    MOVE ERR-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

DECODE-UTF16.
    MOVE 0 TO OUT-COUNT
    IF FUNCTION MOD(CP-COUNT, 2) NOT = 0
        MOVE CP-COUNT TO ERR-POS
        MOVE "unicode.security.C.malformed-utf16.TruncatedCodeUnit" TO ERR-CODE
        PERFORM ADD-ERR-FINDING
    ELSE
        MOVE 1 TO IDX
        PERFORM UNTIL IDX > CP-COUNT OR FINDING-COUNT > 0
            PERFORM READ-U16
            MOVE UNIT-1 TO CODEPOINT
            IF CODEPOINT >= 55296 AND CODEPOINT <= 56319
                IF IDX + 3 > CP-COUNT
                    MOVE CP-COUNT TO ERR-POS
                    MOVE "unicode.security.C.malformed-utf16.TruncatedSurrogatePair" TO ERR-CODE
                    PERFORM ADD-ERR-FINDING
                ELSE
                    ADD 2 TO IDX
                    PERFORM READ-U16
                    MOVE UNIT-1 TO UNIT-2
                    SUBTRACT 2 FROM IDX
                    IF UNIT-2 >= 56320 AND UNIT-2 <= 57343
                        COMPUTE CODEPOINT = 65536 + ((CODEPOINT - 55296) * 1024) + (UNIT-2 - 56320)
                        ADD 1 TO OUT-COUNT
                        MOVE CODEPOINT TO OUT-CP(OUT-COUNT)
                        ADD 4 TO IDX
                    ELSE
                        COMPUTE ERR-POS = IDX + 1
                        MOVE "unicode.security.C.malformed-utf16.InvalidSurrogatePair" TO ERR-CODE
                        PERFORM ADD-ERR-FINDING
                    END-IF
                END-IF
            ELSE
                IF CODEPOINT >= 56320 AND CODEPOINT <= 57343
                    COMPUTE ERR-POS = IDX - 1
                    MOVE "unicode.security.C.malformed-utf16.LoneSurrogate" TO ERR-CODE
                    PERFORM ADD-ERR-FINDING
                ELSE
                    ADD 1 TO OUT-COUNT
                    MOVE CODEPOINT TO OUT-CP(OUT-COUNT)
                    ADD 2 TO IDX
                END-IF
            END-IF
        END-PERFORM
    END-IF.

READ-U16.
    IF ENDIAN-FLAG = "B"
        COMPUTE UNIT-1 = (CP(IDX) * 256) + CP(IDX + 1)
    ELSE
        COMPUTE UNIT-1 = CP(IDX) + (CP(IDX + 1) * 256)
    END-IF.

DECODE-UTF32.
    MOVE 0 TO OUT-COUNT
    IF FUNCTION MOD(CP-COUNT, 4) NOT = 0
        MOVE CP-COUNT TO ERR-POS
        MOVE "unicode.security.C.malformed-utf32.TruncatedCodeUnit" TO ERR-CODE
        PERFORM ADD-ERR-FINDING
    ELSE
        MOVE 1 TO IDX
        PERFORM UNTIL IDX > CP-COUNT OR FINDING-COUNT > 0
            IF ENDIAN-FLAG = "B"
                COMPUTE CODEPOINT = (CP(IDX) * 16777216) + (CP(IDX + 1) * 65536) + (CP(IDX + 2) * 256) + CP(IDX + 3)
            ELSE
                COMPUTE CODEPOINT = CP(IDX) + (CP(IDX + 1) * 256) + (CP(IDX + 2) * 65536) + (CP(IDX + 3) * 16777216)
            END-IF
            IF CODEPOINT >= 55296 AND CODEPOINT <= 57343
                COMPUTE ERR-POS = IDX - 1
                MOVE "unicode.security.C.malformed-utf32.SurrogateCodepoint" TO ERR-CODE
                PERFORM ADD-ERR-FINDING
            ELSE
                IF CODEPOINT > 1114111
                    COMPUTE ERR-POS = IDX - 1
                    MOVE "unicode.security.C.malformed-utf32.CodepointBeyondMax" TO ERR-CODE
                    PERFORM ADD-ERR-FINDING
                ELSE
                    ADD 1 TO OUT-COUNT
                    MOVE CODEPOINT TO OUT-CP(OUT-COUNT)
                    ADD 4 TO IDX
                END-IF
            END-IF
        END-PERFORM
    END-IF.

SCAN-CORE.
    MOVE OUT-COUNT TO CP-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > OUT-COUNT
        MOVE OUT-CP(IDX) TO CP(IDX)
    END-PERFORM
    PERFORM DETECT-TAG-BLOCK
    PERFORM DETECT-VARIATION
    PERFORM DETECT-ZERO-WIDTH
    PERFORM DETECT-SURROGATE-REASSEMBLY
    PERFORM DETECT-BIDI
    PERFORM DETECT-NONCHAR
    PERFORM DETECT-HOMOGLYPH
    PERFORM DETECT-MIXED-SCRIPT
    PERFORM DETECT-RTL
    PERFORM DETECT-CONFUSABLE-BIDI
    PERFORM DETECT-COVERT-DISPLAY
    PERFORM SCAN-EMOJI-ZWJ
    PERFORM SCAN-SKIN-TONE-VARIATION-FORGERY
    PERFORM SCAN-FILENAME-DISGUISE
    PERFORM SCAN-RENDERER-DIVERGENCE
    PERFORM SCAN-STREAM-SAFE
    PERFORM SCAN-CASE-EXPANSION-MISMATCH
    PERFORM SCAN-IDENTIFIER-FORM-DRIFT
    PERFORM SCAN-ADMISSIBILITY-FORM-DRIFT
    PERFORM SCAN-FORMS
    PERFORM SCAN-WIDTH-CLASS-CONFUSION
    PERFORM SCAN-SOURCE-DISPLAY-DIVERGENCE.

DETECT-TAG-BLOCK.
    MOVE 0 TO TAG-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) >= 917504 AND CP(IDX) <= 917631
            ADD 1 TO TAG-COUNT
        END-IF
    END-PERFORM
    IF TAG-COUNT > 0
        IF TAG-COUNT = CP-COUNT
            MOVE "unicode.security.C.tag-block-payload.DirectAscii" TO TEMP-CODE
        ELSE
            MOVE "unicode.security.C.tag-block-payload.MixedBlock" TO TEMP-CODE
        END-IF
        PERFORM ADD-ALL-POS-FINDING
    END-IF.

DETECT-VARIATION.
    MOVE 0 TO VS-COUNT FOUND-FLAG
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF (CP(IDX) >= 65024 AND CP(IDX) <= 65039) OR (CP(IDX) >= 917760 AND CP(IDX) <= 917999) OR (CP(IDX) >= 6155 AND CP(IDX) <= 6157)
            ADD 1 TO VS-COUNT
            MOVE 0 TO TABLE-FLAG
            IF IDX > 1
                MOVE CP(IDX - 1) TO PAIR-BASE
                MOVE CP(IDX) TO PAIR-VS
                PERFORM IS-LEGAL-VARIATION
            END-IF
            IF TABLE-FLAG = 0
                MOVE 1 TO FOUND-FLAG
            END-IF
        END-IF
    END-PERFORM
    IF FOUND-FLAG = 1
        IF VS-COUNT >= 2
            MOVE "unicode.security.C.variation-selector-payload.DirectPayload" TO TEMP-CODE
        ELSE
            MOVE "unicode.security.C.variation-selector-payload.IllegalTarget" TO TEMP-CODE
        END-IF
        PERFORM ADD-VS-POS-FINDING
    END-IF.

DETECT-ZERO-WIDTH.
    MOVE 0 TO ZW-COUNT NNBSP-COUNT ANNO-COUNT WJ-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO LOOKUP-CP
        MOVE 0 TO TABLE-FLAG
        PERFORM IS-DEFAULT-IGNORABLE
        IF CP(IDX) = 8203 OR CP(IDX) = 8205 OR (TABLE-FLAG = 1 AND NOT ((CP(IDX) >= 65024 AND CP(IDX) <= 65039) OR (CP(IDX) >= 917760 AND CP(IDX) <= 917999) OR (CP(IDX) >= 917504 AND CP(IDX) <= 917631) OR (CP(IDX) >= 8234 AND CP(IDX) <= 8238) OR (CP(IDX) >= 8294 AND CP(IDX) <= 8297)))
            ADD 1 TO ZW-COUNT
        END-IF
        IF CP(IDX) = 8239
            ADD 1 TO NNBSP-COUNT
        END-IF
        IF CP(IDX) = 8288
            ADD 1 TO WJ-COUNT
        END-IF
        IF CP(IDX) >= 65529 AND CP(IDX) <= 65531
            ADD 1 TO ANNO-COUNT
        END-IF
    END-PERFORM
    IF ANNO-COUNT > 0
        MOVE "unicode.security.C.zero-width-payload.AnnotationMisuse" TO TEMP-CODE
        PERFORM ADD-ZERO-WIDTH-POS-FINDING
    ELSE
        IF WJ-COUNT > 0
            MOVE "unicode.security.C.zero-width-payload.WordJoinerInjection" TO TEMP-CODE
            PERFORM ADD-ZERO-WIDTH-POS-FINDING
        ELSE
            IF NNBSP-COUNT >= 2
                MOVE "unicode.security.C.zero-width-payload.AiWatermarkNNBSP" TO TEMP-CODE
                PERFORM ADD-ZERO-WIDTH-POS-FINDING
            ELSE
                IF ZW-COUNT >= 2
                    MOVE "unicode.security.C.zero-width-payload.BinaryPayload" TO TEMP-CODE
                    PERFORM ADD-ZERO-WIDTH-POS-FINDING
                ELSE
                    IF ZW-COUNT = 1 OR NNBSP-COUNT = 1
                        MOVE "unicode.security.C.zero-width-payload.BareZeroWidth" TO TEMP-CODE
                        PERFORM ADD-ZERO-WIDTH-POS-FINDING
                    END-IF
                END-IF
            END-IF
        END-IF
    END-IF.

DETECT-SURROGATE-REASSEMBLY.
    IF CP-COUNT > 0
        MOVE 1 TO FOUND-FLAG
        PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
            IF CP(IDX) > 255
                MOVE 0 TO FOUND-FLAG
            END-IF
        END-PERFORM
        IF FOUND-FLAG = 1
            PERFORM FIRST-INVALID-BYTESTREAM
        END-IF
    END-IF.

FIRST-INVALID-BYTESTREAM.
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO BYTE-1
        IF BYTE-1 < 128
            ADD 1 TO IDX
        ELSE
            IF BYTE-1 < 194
                MOVE "unicode.security.C.surrogate-reassembly.InvalidStartByte" TO TEMP-CODE
                PERFORM ADD-ALL-POS-FINDING
                COMPUTE IDX = CP-COUNT + 1
            ELSE
                IF BYTE-1 < 224
                    IF IDX + 1 > CP-COUNT
                        MOVE "unicode.security.C.surrogate-reassembly.Truncated" TO TEMP-CODE
                        PERFORM ADD-ALL-POS-FINDING
                        COMPUTE IDX = CP-COUNT + 1
                    ELSE
                        MOVE CP(IDX + 1) TO BYTE-2
                        IF BYTE-2 < 128 OR BYTE-2 > 191
                            MOVE "unicode.security.C.surrogate-reassembly.InvalidContinuation" TO TEMP-CODE
                            PERFORM ADD-ALL-POS-FINDING
                            COMPUTE IDX = CP-COUNT + 1
                        ELSE
                            ADD 2 TO IDX
                        END-IF
                    END-IF
                ELSE
                    IF BYTE-1 = 224 AND IDX + 2 <= CP-COUNT AND CP(IDX + 1) = 128
                        MOVE "unicode.security.C.surrogate-reassembly.Overlong" TO TEMP-CODE
                        PERFORM ADD-ALL-POS-FINDING
                        COMPUTE IDX = CP-COUNT + 1
                    ELSE
                        IF BYTE-1 = 237 AND IDX + 2 <= CP-COUNT AND CP(IDX + 1) >= 160
                            MOVE "unicode.security.C.surrogate-reassembly.Cesu8" TO TEMP-CODE
                            PERFORM ADD-ALL-POS-FINDING
                            COMPUTE IDX = CP-COUNT + 1
                        ELSE
                            IF BYTE-1 < 240
                                ADD 3 TO IDX
                            ELSE
                                ADD 4 TO IDX
                            END-IF
                        END-IF
                    END-IF
                END-IF
            END-IF
        END-IF
    END-PERFORM.

DETECT-BIDI.
    MOVE 0 TO EMB-DEPTH ISO-DEPTH ORPHAN-POS MAX-DEPTH
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) = 8234 OR CP(IDX) = 8235 OR CP(IDX) = 8237 OR CP(IDX) = 8238
            ADD 1 TO EMB-DEPTH
            IF EMB-DEPTH + ISO-DEPTH > MAX-DEPTH
                COMPUTE MAX-DEPTH = EMB-DEPTH + ISO-DEPTH
            END-IF
        ELSE
            IF CP(IDX) = 8236
                IF EMB-DEPTH > 0
                    SUBTRACT 1 FROM EMB-DEPTH
                ELSE
                    COMPUTE ORPHAN-POS = IDX - 1
                END-IF
            ELSE
                IF CP(IDX) = 8294 OR CP(IDX) = 8295 OR CP(IDX) = 8296
                    ADD 1 TO ISO-DEPTH
                ELSE
                    IF CP(IDX) = 8297
                        IF ISO-DEPTH > 0
                            SUBTRACT 1 FROM ISO-DEPTH
                        ELSE
                            COMPUTE ORPHAN-POS = IDX - 1
                        END-IF
                    END-IF
                END-IF
            END-IF
        END-IF
    END-PERFORM
    IF MAX-DEPTH > 125
        MOVE "unicode.security.C.bidi-control-balance.DepthExceeded" TO TEMP-CODE
        PERFORM ADD-BIDI-POS-FINDING
    ELSE
        IF ORPHAN-POS > 0
            MOVE "unicode.security.C.bidi-control-balance.OrphanPop" TO TEMP-CODE
            PERFORM ADD-BIDI-POS-FINDING
        ELSE
            IF EMB-DEPTH > 0
                MOVE "unicode.security.C.bidi-control-balance.UnbalancedEmbedding" TO TEMP-CODE
                PERFORM ADD-BIDI-POS-FINDING
            ELSE
                IF ISO-DEPTH > 0
                    MOVE "unicode.security.C.bidi-control-balance.UnbalancedIsolate" TO TEMP-CODE
                    PERFORM ADD-BIDI-POS-FINDING
                END-IF
            END-IF
        END-IF
    END-IF.

DETECT-NONCHAR.
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF (CP(IDX) >= 64976 AND CP(IDX) <= 65007) OR FUNCTION MOD(CP(IDX), 65536) = 65534 OR FUNCTION MOD(CP(IDX), 65536) = 65535
            MOVE "unicode.security.C.noncharacter-control.Noncharacter" TO TEMP-CODE
            PERFORM ADD-ALL-POS-FINDING
            MOVE CP-COUNT TO IDX
        ELSE
            IF (CP(IDX) <= 31 AND CP(IDX) NOT = 9 AND CP(IDX) NOT = 10 AND CP(IDX) NOT = 13) OR CP(IDX) = 127
                MOVE "unicode.security.C.noncharacter-control.C0Control" TO TEMP-CODE
                PERFORM ADD-ALL-POS-FINDING
                MOVE CP-COUNT TO IDX
            ELSE
                IF CP(IDX) >= 128 AND CP(IDX) <= 159
                    MOVE "unicode.security.C.noncharacter-control.C1Control" TO TEMP-CODE
                    PERFORM ADD-ALL-POS-FINDING
                    MOVE CP-COUNT TO IDX
                END-IF
            END-IF
        END-IF
    END-PERFORM.

DETECT-HOMOGLYPH.
    MOVE 0 TO FOUND-FLAG
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) = 1077 OR CP(IDX) = 1072 OR CP(IDX) = 233 OR CP(IDX) = 223 OR CP(IDX) = 946
            MOVE 1 TO FOUND-FLAG
        END-IF
        IF CP(IDX) >= 119808 AND CP(IDX) <= 120831 AND CP-COUNT > 1
            MOVE 1 TO FOUND-FLAG
        END-IF
        IF CP(IDX) >= 65281 AND CP(IDX) <= 65519 AND CP-COUNT > 1
            MOVE 1 TO FOUND-FLAG
        END-IF
    END-PERFORM
    IF FOUND-FLAG = 1
        MOVE "unicode.security.I.homoglyph-confusable.TargetMatch" TO TEMP-CODE
        PERFORM ADD-ALL-POS-FINDING
    ELSE
        PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
            IF CP(IDX) >= 119808 AND CP(IDX) <= 120831
                MOVE "unicode.security.I.homoglyph-confusable.MathAlpha" TO TEMP-CODE
                PERFORM ADD-ALL-POS-FINDING
                MOVE CP-COUNT TO IDX
            ELSE
                IF CP(IDX) >= 65281 AND CP(IDX) <= 65519
                    MOVE "unicode.security.I.homoglyph-confusable.WidthClass" TO TEMP-CODE
                    PERFORM ADD-ALL-POS-FINDING
                    MOVE CP-COUNT TO IDX
                ELSE
                    IF CP(IDX) = 769
                        MOVE "unicode.security.I.homoglyph-confusable.DecompositionSwap" TO TEMP-CODE
                        PERFORM ADD-ALL-POS-FINDING
                        MOVE CP-COUNT TO IDX
                    END-IF
                END-IF
            END-IF
        END-PERFORM
    END-IF.

DETECT-MIXED-SCRIPT.
    MOVE 0 TO HAS-LATN HAS-GREK HAS-CYRL
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM APPLY-SCRIPT-FLAGS
    END-PERFORM
    IF HAS-LATN = 1 AND HAS-CYRL = 1
        MOVE "unicode.security.I.mixed-script-admissibility.LatinCyrillic" TO TEMP-CODE
        PERFORM ADD-ALL-POS-FINDING
    ELSE
        IF HAS-LATN = 1 AND HAS-GREK = 1
            MOVE "unicode.security.I.mixed-script-admissibility.LatinGreek" TO TEMP-CODE
            PERFORM ADD-ALL-POS-FINDING
        END-IF
    END-IF.

DETECT-RTL.
    MOVE 0 TO RTL-RUN RTL-BEST RTL-BEST-START FIRST-RTL FOUND-FLAG
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) = 8234 OR CP(IDX) = 8235 OR CP(IDX) = 8237 OR CP(IDX) = 8238 OR CP(IDX) = 8236 OR CP(IDX) = 8294 OR CP(IDX) = 8295 OR CP(IDX) = 8296 OR CP(IDX) = 8297
            MOVE "unicode.security.D.rtl-injection.RloInLTRField" TO TEMP-CODE
            PERFORM ADD-BIDI-POS-FINDING
            MOVE 1 TO FOUND-FLAG
            MOVE CP-COUNT TO IDX
        ELSE
            MOVE CP(IDX) TO LOOKUP-CP
            MOVE 0 TO TABLE-FLAG
            PERFORM IS-STRONG-RTL
            IF TABLE-FLAG = 1
                IF FIRST-RTL = 0
                    MOVE IDX TO FIRST-RTL
                END-IF
                ADD 1 TO RTL-RUN
                IF RTL-RUN > RTL-BEST
                    MOVE RTL-RUN TO RTL-BEST
                    COMPUTE RTL-BEST-START = IDX - RTL-RUN
                END-IF
            ELSE
                MOVE 0 TO RTL-RUN
            END-IF
        END-IF
    END-PERFORM
    IF FOUND-FLAG = 0 AND FIRST-RTL > 0
        IF FIRST-RTL = 1
            MOVE "unicode.security.D.rtl-injection.FieldTakeover" TO TEMP-CODE
        ELSE
            IF RTL-BEST >= 4
                MOVE "unicode.security.D.rtl-injection.MixedOverflow" TO TEMP-CODE
            ELSE
                MOVE "unicode.security.D.rtl-injection.StrongRTLInLTR" TO TEMP-CODE
            END-IF
        END-IF
        PERFORM ADD-ALL-POS-FINDING
    END-IF.

DETECT-CONFUSABLE-BIDI.
    MOVE 0 TO HAS-CONFUSABLE HAS-OVERRIDE HAS-ISOLATE
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO LOOKUP-CP
        MOVE 0 TO TABLE-FLAG
        PERFORM IS-CONFUSABLE-SOURCE
        IF TABLE-FLAG = 1
            MOVE 1 TO HAS-CONFUSABLE
        END-IF
        IF CP(IDX) = 8234 OR CP(IDX) = 8235 OR CP(IDX) = 8237 OR CP(IDX) = 8238 OR CP(IDX) = 8236
            MOVE 1 TO HAS-OVERRIDE
        END-IF
        IF CP(IDX) = 8294 OR CP(IDX) = 8295 OR CP(IDX) = 8296 OR CP(IDX) = 8297
            MOVE 1 TO HAS-ISOLATE
        END-IF
    END-PERFORM
    IF HAS-CONFUSABLE = 1 AND HAS-OVERRIDE = 1
        MOVE "unicode.security.X.confusable-bidi-compound.ConfusableInOverride" TO TEMP-CODE
        PERFORM ADD-ALL-POS-FINDING
    ELSE
        IF HAS-CONFUSABLE = 1 AND HAS-ISOLATE = 1
            MOVE "unicode.security.X.confusable-bidi-compound.ConfusableInIsolate" TO TEMP-CODE
            PERFORM ADD-ALL-POS-FINDING
        END-IF
    END-IF.

DETECT-COVERT-DISPLAY.
    MOVE 0 TO HAS-BIDI HAS-TAG HAS-BAD-VS
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) = 8234 OR CP(IDX) = 8235 OR CP(IDX) = 8237 OR CP(IDX) = 8238 OR CP(IDX) = 8236 OR CP(IDX) = 8294 OR CP(IDX) = 8295 OR CP(IDX) = 8296 OR CP(IDX) = 8297
            MOVE 1 TO HAS-BIDI
        END-IF
        IF CP(IDX) >= 917504 AND CP(IDX) <= 917631
            MOVE 1 TO HAS-TAG
        END-IF
        IF (CP(IDX) >= 65024 AND CP(IDX) <= 65039) OR (CP(IDX) >= 917760 AND CP(IDX) <= 917999) OR (CP(IDX) >= 6155 AND CP(IDX) <= 6157)
            MOVE 0 TO TABLE-FLAG
            IF IDX > 1
                MOVE CP(IDX - 1) TO PAIR-BASE
                MOVE CP(IDX) TO PAIR-VS
                PERFORM IS-LEGAL-VARIATION
            END-IF
            IF TABLE-FLAG = 0
                MOVE 1 TO HAS-BAD-VS
            END-IF
        END-IF
    END-PERFORM
    IF HAS-BIDI = 1 AND HAS-BAD-VS = 1
        MOVE "unicode.security.X.covert-display-compound.BidiPlusUnregisteredVs" TO TEMP-CODE
        PERFORM ADD-ALL-POS-FINDING
    ELSE
        IF HAS-BIDI = 1 AND HAS-TAG = 1
            MOVE "unicode.security.X.covert-display-compound.BidiPlusTagBlock" TO TEMP-CODE
            PERFORM ADD-ALL-POS-FINDING
        END-IF
    END-IF.

SCAN-FORMS.
*> The three form-layer detectors the reference dispatches on plain input, in
*> its order: normalization-bomb, then locale-case-inversion, then
*> nfc-idempotence-witness. Each walks the whole input rather than testing the
*> leading codepoint, and each reports the first divergence, which is what the
*> reference localises.
    PERFORM SCAN-NORMALIZATION-BOMB
    PERFORM SCAN-LOCALE-CASE-INVERSION
    PERFORM SCAN-NFC-IDEMPOTENCE-WITNESS.

SCAN-NORMALIZATION-BOMB.
*> UAX #15 expansion hazards. A single codepoint whose compatibility
*> decomposition exceeds MAX-NFKD-PER-CP (8) is reported at its own index;
*> otherwise the whole-sequence ratios are tested, NFKD above 4x then NFD above
*> 3x, both strict so pure Hangul at exactly 3x stays clear. The ratio hazards
*> implicate the input as a unit and carry no position.
    MOVE 0 TO NB-FOUND
    IF CP-COUNT > 0
        PERFORM VARYING IDX FROM 1 BY 1
                UNTIL IDX > CP-COUNT OR NB-FOUND = 1
            MOVE 0 TO NFD-COUNT
            MOVE CP(IDX) TO CUR-CP
            PERFORM COMPAT-DECOMPOSE-ONE
            IF NFD-COUNT > 8
                MOVE 1 TO NB-FOUND
                COMPUTE ONE-POS = IDX - 1
                MOVE "unicode.security.F.normalization-bomb.SingleCpBlowup"
                    TO TEMP-CODE
                PERFORM ADD-ONE-POS-FINDING
            END-IF
        END-PERFORM
        IF NB-FOUND = 0
            PERFORM DECOMPOSE-INPUT-COMPAT
            COMPUTE NB-RATIO = NFD-COUNT * 100 / CP-COUNT
            IF NB-RATIO > 400
                MOVE 1 TO NB-FOUND
                MOVE "unicode.security.F.normalization-bomb.NfkdHighExpansion"
                    TO TEMP-CODE
                PERFORM ADD-NO-POS-FINDING
            END-IF
        END-IF
        IF NB-FOUND = 0
            PERFORM DECOMPOSE-INPUT
            COMPUTE NB-RATIO = NFD-COUNT * 100 / CP-COUNT
            IF NB-RATIO > 300
                MOVE "unicode.security.F.normalization-bomb.NfdHighExpansion"
                    TO TEMP-CODE
                PERFORM ADD-NO-POS-FINDING
            END-IF
        END-IF
    END-IF.

SCAN-LOCALE-CASE-INVERSION.
*> An input whose lowercase fold inverts across locales. Turkish is tested
*> first and Lithuanian only when Turkish finds nothing, matching the
*> reference's priority. The comparison is the real one: at each position the
*> context-sensitive default lowercase mapping is computed and held, then the
*> locale mapping is computed over the same context, and the first position at
*> which they differ is the divergence.
    MOVE 1 TO LCI-LOCALE
    PERFORM LCI-FIND-DIVERGENCE
    IF LCI-FOUND = 1
        MOVE LCI-POS TO ONE-POS
        MOVE "unicode.security.F.locale-case-inversion.TurkishCaseDivergence"
            TO TEMP-CODE
        PERFORM ADD-ONE-POS-FINDING
    ELSE
        MOVE 3 TO LCI-LOCALE
        PERFORM LCI-FIND-DIVERGENCE
        IF LCI-FOUND = 1
            MOVE LCI-POS TO ONE-POS
            MOVE
              "unicode.security.F.locale-case-inversion.LithuanianCaseDivergence"
                TO TEMP-CODE
            PERFORM ADD-ONE-POS-FINDING
        END-IF
    END-IF.

LCI-FIND-DIVERGENCE.
*> First 0-based index whose default lowercase differs from the LCI-LOCALE
*> lowercase, or LCI-FOUND = 0 when none does. COMPUTE-CASE-CONTEXT sets the
*> UAX #21 context flags for CE-IDX, which both mappings then read, so the two
*> differ only in the locale discriminant.
    MOVE 0 TO LCI-FOUND
    MOVE 0 TO LCI-POS
    PERFORM VARYING CE-IDX FROM 1 BY 1
            UNTIL CE-IDX > CP-COUNT OR LCI-FOUND = 1
        PERFORM COMPUTE-CASE-CONTEXT
        MOVE 0 TO SC-LOCALE
        PERFORM LOWER-CODEPOINT
        MOVE LC-LEN TO LCI-DEF-LEN
        PERFORM VARYING LCI-CMP-IDX FROM 1 BY 1
                UNTIL LCI-CMP-IDX > LC-LEN OR LCI-CMP-IDX > 3
            MOVE LC-CP(LCI-CMP-IDX) TO LCI-DEF-CP(LCI-CMP-IDX)
        END-PERFORM
        MOVE LCI-LOCALE TO SC-LOCALE
        PERFORM LOWER-CODEPOINT
        MOVE 0 TO LCI-DIFF
        IF LC-LEN NOT = LCI-DEF-LEN
            MOVE 1 TO LCI-DIFF
        ELSE
            PERFORM VARYING LCI-CMP-IDX FROM 1 BY 1
                    UNTIL LCI-CMP-IDX > LC-LEN OR LCI-CMP-IDX > 3
                IF LC-CP(LCI-CMP-IDX) NOT = LCI-DEF-CP(LCI-CMP-IDX)
                    MOVE 1 TO LCI-DIFF
                END-IF
            END-PERFORM
        END-IF
        IF LCI-DIFF = 1
            MOVE 1 TO LCI-FOUND
            COMPUTE LCI-POS = CE-IDX - 1
        END-IF
    END-PERFORM
    MOVE 0 TO SC-LOCALE.

SCAN-NFC-IDEMPOTENCE-WITNESS.
*> An input that is not already in canonical form, or not in compatibility
*> form. NFC divergence takes priority over NFKC. The position reported is the
*> first index at which the input and its normalization differ, or the length
*> of the shorter of the two when one is a prefix of the other.
    MOVE 0 TO NFCW-FOUND
    PERFORM COMPUTE-NFC
    PERFORM NFCW-FIRST-DIVERGENCE
    IF NFCW-FOUND = 1
        MOVE NFCW-POS TO ONE-POS
        MOVE "unicode.security.F.nfc-idempotence-witness.NonNfcForm"
            TO TEMP-CODE
        PERFORM ADD-ONE-POS-FINDING
    ELSE
        PERFORM COMPUTE-NFKC
        PERFORM NFCW-FIRST-DIVERGENCE
        IF NFCW-FOUND = 1
            MOVE NFCW-POS TO ONE-POS
            MOVE
              "unicode.security.F.nfc-idempotence-witness.NonNfkcCompatForm"
                TO TEMP-CODE
            PERFORM ADD-ONE-POS-FINDING
        END-IF
    END-IF.

NFCW-FIRST-DIVERGENCE.
*> Compare CP(1..CP-COUNT) against the normalized NFC-CP(1..NFC-COUNT) most
*> recently computed. Sets NFCW-FOUND and the 0-based NFCW-POS.
    MOVE 0 TO NFCW-FOUND
    MOVE 0 TO NFCW-POS
    MOVE CP-COUNT TO NFCW-COMMON
    IF NFC-COUNT < NFCW-COMMON
        MOVE NFC-COUNT TO NFCW-COMMON
    END-IF
    PERFORM VARYING IDX FROM 1 BY 1
            UNTIL IDX > NFCW-COMMON OR NFCW-FOUND = 1
        IF CP(IDX) NOT = NFC-CP(IDX)
            MOVE 1 TO NFCW-FOUND
            COMPUTE NFCW-POS = IDX - 1
        END-IF
    END-PERFORM
    IF NFCW-FOUND = 0 AND CP-COUNT NOT = NFC-COUNT
        MOVE 1 TO NFCW-FOUND
        MOVE NFCW-COMMON TO NFCW-POS
    END-IF.

SCAN-BIP39.
    MOVE 0 TO TRAILING-WS UPPER-FLAG DOUBLE-WS UNKNOWN-WORD WORDLIST-MISMATCH PREV-WS
    IF CP-COUNT > 0 AND (CP(CP-COUNT) = 32 OR CP(CP-COUNT) = 12288)
        MOVE 1 TO TRAILING-WS
    END-IF
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) >= 65 AND CP(IDX) <= 90
            MOVE 1 TO UPPER-FLAG
        END-IF
        IF CP(IDX) = 32 OR CP(IDX) = 12288
            IF PREV-WS = 1
                MOVE 1 TO DOUBLE-WS
            END-IF
            MOVE 1 TO PREV-WS
        ELSE
            MOVE 0 TO PREV-WS
        END-IF
        IF CP(IDX) = 64256
            MOVE 1 TO UNKNOWN-WORD
        END-IF
    END-PERFORM
    PERFORM CHECK-BIP39-WORDS
    IF TRAILING-WS = 1
        MOVE "unicode.security.K.bip39-canonical.TrailingWhitespace" TO TEMP-CODE
        PERFORM ADD-ALL-POS-FINDING
    ELSE
        IF UPPER-FLAG = 1
            MOVE "unicode.security.K.bip39-canonical.MixedCase" TO TEMP-CODE
            PERFORM ADD-ALL-POS-FINDING
        ELSE
            IF DOUBLE-WS = 1
                MOVE "unicode.security.K.bip39-canonical.WhitespaceAnomaly" TO TEMP-CODE
                PERFORM ADD-ALL-POS-FINDING
            ELSE
                IF UNKNOWN-WORD = 1
                    MOVE "unicode.security.K.bip39-canonical.NonNFKD" TO TEMP-CODE
                    PERFORM ADD-ALL-POS-FINDING
                ELSE
                    IF WORDLIST-MISMATCH = 1
                        MOVE "unicode.security.K.bip39-canonical.WordlistMismatch" TO TEMP-CODE
                        PERFORM ADD-ALL-POS-FINDING
                    END-IF
                END-IF
            END-IF
        END-IF
    END-IF.

CHECK-BIP39-WORDS.
    MOVE SPACES TO WORD-KEY
    MOVE 1 TO WORD-PTR WORD-FIRST-CP
    MOVE 0 TO WORD-HAS-CHARS
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT + 1
        IF IDX > CP-COUNT OR CP(IDX) = 32 OR CP(IDX) = 12288
            IF WORD-HAS-CHARS = 1
                MOVE 0 TO TABLE-FLAG
                PERFORM IS-BIP39-WORD
                IF TABLE-FLAG = 0
                    MOVE 1 TO WORDLIST-MISMATCH
                END-IF
            END-IF
            MOVE SPACES TO WORD-KEY
            MOVE 1 TO WORD-PTR WORD-FIRST-CP
            MOVE 0 TO WORD-HAS-CHARS
        ELSE
            MOVE 1 TO WORD-HAS-CHARS
            MOVE CP(IDX) TO POS-NUM
            IF WORD-FIRST-CP = 1
                STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO WORD-KEY WITH POINTER WORD-PTR
                MOVE 0 TO WORD-FIRST-CP
            ELSE
                STRING "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO WORD-KEY WITH POINTER WORD-PTR
            END-IF
        END-IF
    END-PERFORM.

SCAN-HASH-INPUT-STABILITY.
    MOVE 0 TO HIS-DONE
    PERFORM PARSE-HIS-CONTEXT
    IF HIS-DONE = 0
        PERFORM PROBE-ENCODING
    END-IF
    IF HIS-DONE = 0
        PERFORM PROBE-WEBHOOK
    END-IF
    IF HIS-DONE = 0
        PERFORM PROBE-AUDIT
    END-IF
    IF HIS-DONE = 0
        PERFORM PROBE-RFC
    END-IF
    IF HIS-DONE = 0
        PERFORM PROBE-TRAILING
    END-IF
    IF HIS-DONE = 0
        PERFORM PROBE-NORMALIZATION
    END-IF.

PARSE-HIS-CONTEXT.
    MOVE 0 TO ENC-ACTIVE RFC-ACTIVE AUDIT-ACTIVE WEBHOOK-ACTIVE
    MOVE 0 TO AW-COUNT SV-COUNT
    IF FUNCTION TRIM(ENC-ARG) NOT = "-"
        MOVE 1 TO ENC-ACTIVE
    END-IF
    IF FUNCTION TRIM(RFC-ARG) NOT = "-"
        MOVE 1 TO RFC-ACTIVE
    END-IF
    IF FUNCTION TRIM(AUDIT-ARG) NOT = "-"
        MOVE 1 TO AUDIT-ACTIVE
        MOVE AUDIT-ARG TO SIDE-SRC
        PERFORM PARSE-SIDE-LIST
        MOVE SIDE-COUNT TO AW-COUNT
        PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > SIDE-COUNT
            MOVE SIDE-CP(IDX) TO AW-CP(IDX)
        END-PERFORM
    END-IF
    IF FUNCTION TRIM(WEBHOOK-ARG) NOT = "-"
        MOVE 1 TO WEBHOOK-ACTIVE
        MOVE WEBHOOK-ARG TO SIDE-SRC
        PERFORM PARSE-SIDE-LIST
        MOVE SIDE-COUNT TO SV-COUNT
        PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > SIDE-COUNT
            MOVE SIDE-CP(IDX) TO SV-CP(IDX)
        END-PERFORM
    END-IF.

PARSE-SIDE-LIST.
    MOVE 0 TO SIDE-COUNT CUR-NUM IN-NUM
    MOVE FUNCTION LENGTH(FUNCTION TRIM(SIDE-SRC)) TO SIDE-LEN
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > SIDE-LEN
        MOVE SIDE-SRC(IDX:1) TO CHAR-1
        IF CHAR-1 >= "0" AND CHAR-1 <= "9"
            COMPUTE CUR-NUM = (CUR-NUM * 10) + FUNCTION NUMVAL(CHAR-1)
            MOVE 1 TO IN-NUM
        ELSE
            IF IN-NUM = 1
                ADD 1 TO SIDE-COUNT
                MOVE CUR-NUM TO SIDE-CP(SIDE-COUNT)
                MOVE 0 TO CUR-NUM IN-NUM
            END-IF
        END-IF
    END-PERFORM
    IF IN-NUM = 1
        ADD 1 TO SIDE-COUNT
        MOVE CUR-NUM TO SIDE-CP(SIDE-COUNT)
    END-IF.

PROBE-ENCODING.
    IF ENC-ACTIVE = 1
        MOVE 0 TO FOUND-FLAG
        PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT OR FOUND-FLAG = 1
            IF CP(IDX) > 1114111 OR (CP(IDX) >= 55296 AND CP(IDX) <= 57343)
                COMPUTE HIS-POS = IDX - 1
                MOVE 1 TO FOUND-FLAG
            END-IF
        END-PERFORM
        IF FOUND-FLAG = 1
            MOVE "unicode.security.K.hash-input-stability.EncodingMismatch" TO TEMP-CODE
            PERFORM ADD-HIS-FINDING
            MOVE 1 TO HIS-DONE
        ELSE
            MOVE FUNCTION UPPER-CASE(FUNCTION TRIM(ENC-ARG)) TO ENC-UPPER
            IF ENC-UPPER NOT = "UTF-8" AND ENC-UPPER NOT = "UTF8"
                MOVE 0 TO HIS-POS
                MOVE "unicode.security.K.hash-input-stability.EncodingMismatch" TO TEMP-CODE
                PERFORM ADD-HIS-FINDING
                MOVE 1 TO HIS-DONE
            END-IF
        END-IF
    END-IF.

PROBE-WEBHOOK.
    IF WEBHOOK-ACTIVE = 1
        PERFORM COPY-CP-TO-A
        PERFORM COPY-SV-TO-B
        PERFORM FIRST-DIV
        IF DIV-FOUND = 1
            MOVE DIV-POS TO HIS-POS
            MOVE "unicode.security.K.hash-input-stability.WebhookSignatureDrift" TO TEMP-CODE
            PERFORM ADD-HIS-FINDING
            MOVE 1 TO HIS-DONE
        END-IF
    END-IF.

PROBE-AUDIT.
    IF AUDIT-ACTIVE = 1
        PERFORM COPY-AW-TO-A
        PERFORM COPY-CP-TO-B
        PERFORM FIRST-DIV
        IF DIV-FOUND = 1
            MOVE DIV-POS TO HIS-POS
            MOVE "unicode.security.K.hash-input-stability.AuditLogReinterpretation" TO TEMP-CODE
            PERFORM ADD-HIS-FINDING
            MOVE 1 TO HIS-DONE
        END-IF
    END-IF.

PROBE-RFC.
    IF RFC-ACTIVE = 1
        MOVE FUNCTION TRIM(RFC-ARG) TO RFC-TAG
        MOVE 0 TO FOUND-FLAG
        EVALUATE RFC-TAG
        WHEN "pgp4880TrailingWhitespace"
            PERFORM RFC-PGP4880
        WHEN "pgp9580LineEnding"
            PERFORM RFC-BARE-LINE-ENDING
        WHEN "rfc8785NfcRequirement"
            PERFORM RFC-8785-NFC
        WHEN "rfc8259ControlChar"
            PERFORM RFC-8259-CONTROL
        WHEN "rfc7515JwsBase64Url"
            PERFORM RFC-7515-BASE64URL
        WHEN "rfc6376DkimRelaxed"
            PERFORM RFC-6376-DKIM
        WHEN "rfc5751SmimeLineEnding"
            PERFORM RFC-BARE-LINE-ENDING
        WHEN OTHER
            CONTINUE
        END-EVALUATE
        IF FOUND-FLAG = 1
            MOVE "unicode.security.K.hash-input-stability.SignedMessageRule" TO TEMP-CODE
            PERFORM ADD-HIS-FINDING
            MOVE 1 TO HIS-DONE
        END-IF
    END-IF.

RFC-PGP4880.
    PERFORM COUNT-TRAILING
    IF TRAIL-COUNT > 0
        COMPUTE HIS-POS = CP-COUNT - TRAIL-COUNT
        MOVE 1 TO FOUND-FLAG
    END-IF.

RFC-BARE-LINE-ENDING.
    MOVE 0 TO FOUND-FLAG
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT OR FOUND-FLAG = 1
        IF CP(IDX) = 10
            IF IDX = 1
                COMPUTE HIS-POS = IDX - 1
                MOVE 1 TO FOUND-FLAG
            ELSE
                IF CP(IDX - 1) NOT = 13
                    COMPUTE HIS-POS = IDX - 1
                    MOVE 1 TO FOUND-FLAG
                END-IF
            END-IF
        ELSE
            IF CP(IDX) = 13
                IF IDX >= CP-COUNT
                    COMPUTE HIS-POS = IDX - 1
                    MOVE 1 TO FOUND-FLAG
                ELSE
                    IF CP(IDX + 1) NOT = 10
                        COMPUTE HIS-POS = IDX - 1
                        MOVE 1 TO FOUND-FLAG
                    END-IF
                END-IF
            END-IF
        END-IF
    END-PERFORM.

RFC-8785-NFC.
    PERFORM COMPUTE-NFC
    PERFORM COPY-CP-TO-A
    PERFORM COPY-NFC-TO-B
    PERFORM FIRST-DIV
    IF DIV-FOUND = 1
        MOVE DIV-POS TO HIS-POS
        MOVE 1 TO FOUND-FLAG
    END-IF.

RFC-8259-CONTROL.
    MOVE 0 TO FOUND-FLAG
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT OR FOUND-FLAG = 1
        IF CP(IDX) <= 31
            COMPUTE HIS-POS = IDX - 1
            MOVE 1 TO FOUND-FLAG
        END-IF
    END-PERFORM.

RFC-7515-BASE64URL.
    MOVE 0 TO FOUND-FLAG
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT OR FOUND-FLAG = 1
        IF NOT ((CP(IDX) >= 65 AND CP(IDX) <= 90) OR (CP(IDX) >= 97 AND CP(IDX) <= 122) OR (CP(IDX) >= 48 AND CP(IDX) <= 57) OR CP(IDX) = 45 OR CP(IDX) = 95)
            COMPUTE HIS-POS = IDX - 1
            MOVE 1 TO FOUND-FLAG
        END-IF
    END-PERFORM.

RFC-6376-DKIM.
    MOVE 0 TO FOUND-FLAG
    PERFORM VARYING IDX FROM 2 BY 1 UNTIL IDX > CP-COUNT OR FOUND-FLAG = 1
        IF (CP(IDX) = 32 OR CP(IDX) = 9) AND (CP(IDX - 1) = 32 OR CP(IDX - 1) = 9)
            COMPUTE HIS-POS = IDX - 1
            MOVE 1 TO FOUND-FLAG
        END-IF
    END-PERFORM.

PROBE-TRAILING.
    PERFORM COUNT-TRAILING
    IF TRAIL-COUNT > 0
        COMPUTE HIS-POS = CP-COUNT - TRAIL-COUNT
        MOVE "unicode.security.K.hash-input-stability.TrailingWhitespace" TO TEMP-CODE
        PERFORM ADD-HIS-FINDING
        MOVE 1 TO HIS-DONE
    END-IF.

PROBE-NORMALIZATION.
    PERFORM COMPUTE-NFC
    PERFORM COPY-CP-TO-A
    PERFORM COPY-NFC-TO-B
    PERFORM FIRST-DIV
    IF DIV-FOUND = 1
        MOVE DIV-POS TO HIS-POS
        MOVE "unicode.security.K.hash-input-stability.NormalizationDrift" TO TEMP-CODE
        PERFORM ADD-HIS-FINDING
        MOVE 1 TO HIS-DONE
    END-IF.

COUNT-TRAILING.
    MOVE 0 TO TRAIL-COUNT BREAK-FLAG
    PERFORM VARYING IDX FROM CP-COUNT BY -1 UNTIL IDX < 1 OR BREAK-FLAG = 1
        IF CP(IDX) = 32 OR CP(IDX) = 9 OR CP(IDX) = 10 OR CP(IDX) = 13
            ADD 1 TO TRAIL-COUNT
        ELSE
            MOVE 1 TO BREAK-FLAG
        END-IF
    END-PERFORM.

FIRST-DIV.
    MOVE 0 TO DIV-FOUND
    IF A-COUNT < B-COUNT
        MOVE A-COUNT TO COMMON-LEN
    ELSE
        MOVE B-COUNT TO COMMON-LEN
    END-IF
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > COMMON-LEN OR DIV-FOUND = 1
        IF A-CP(JDX) NOT = B-CP(JDX)
            COMPUTE DIV-POS = JDX - 1
            MOVE 1 TO DIV-FOUND
        END-IF
    END-PERFORM
    IF DIV-FOUND = 0 AND A-COUNT NOT = B-COUNT
        MOVE COMMON-LEN TO DIV-POS
        MOVE 1 TO DIV-FOUND
    END-IF.

COPY-CP-TO-A.
    MOVE CP-COUNT TO A-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO A-CP(IDX)
    END-PERFORM.

COPY-CP-TO-B.
    MOVE CP-COUNT TO B-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO B-CP(IDX)
    END-PERFORM.

COPY-NFC-TO-B.
    MOVE NFC-COUNT TO B-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > NFC-COUNT
        MOVE NFC-CP(IDX) TO B-CP(IDX)
    END-PERFORM.

COPY-SV-TO-B.
    MOVE SV-COUNT TO B-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > SV-COUNT
        MOVE SV-CP(IDX) TO B-CP(IDX)
    END-PERFORM.

COPY-AW-TO-A.
    MOVE AW-COUNT TO A-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > AW-COUNT
        MOVE AW-CP(IDX) TO A-CP(IDX)
    END-PERFORM.

COMPUTE-NFC.
    PERFORM DECOMPOSE-INPUT
    PERFORM REORDER-NFD
    PERFORM COMPOSE-NFD.

COMPUTE-NFKC.
*> NFKC of the input into NFC-CP/NFC-COUNT: compatibility-decompose (NFKD)
*> the whole input, canonically reorder, then canonically compose. Reuses the
*> port's own COMPAT-DECOMPOSE-ONE, REORDER-NFD, and COMPOSE-NFD — the same
*> pieces COMPUTE-NFC and the identifier-form-drift NFKD head use — so no host
*> normalization library is involved.
    PERFORM DECOMPOSE-INPUT-COMPAT
    PERFORM REORDER-NFD
    PERFORM COMPOSE-NFD.

DECOMPOSE-INPUT-COMPAT.
*> Full NFKD (compatibility) decomposition of every input codepoint appended
*> into the shared NFD scratch, mirroring DECOMPOSE-INPUT but following the
*> compatibility mapping via COMPAT-DECOMPOSE-ONE.
    MOVE 0 TO NFD-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO CUR-CP
        PERFORM COMPAT-DECOMPOSE-ONE
    END-PERFORM.

DECOMPOSE-INPUT.
    MOVE 0 TO NFD-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO CUR-CP
        PERFORM DECOMPOSE-ONE
    END-PERFORM.

DECOMPOSE-ONE.
    IF CUR-CP >= 44032 AND CUR-CP < 55204
        COMPUTE HS-INDEX = CUR-CP - 44032
        COMPUTE HL-VAL = 4352 + (HS-INDEX / 588)
        COMPUTE HV-VAL = 4449 + (FUNCTION MOD(HS-INDEX, 588) / 28)
        COMPUTE HT-INDEX = FUNCTION MOD(HS-INDEX, 28)
        ADD 1 TO NFD-COUNT
        MOVE HL-VAL TO NFD-CP(NFD-COUNT)
        ADD 1 TO NFD-COUNT
        MOVE HV-VAL TO NFD-CP(NFD-COUNT)
        IF HT-INDEX NOT = 0
            ADD 1 TO NFD-COUNT
            COMPUTE NFD-CP(NFD-COUNT) = 4519 + HT-INDEX
        END-IF
    ELSE
        MOVE CUR-CP TO LOOKUP-CP
        PERFORM LOOKUP-CANON-DECOMP
        IF DEC-FOUND = 1
            PERFORM VARYING KDX FROM 1 BY 1 UNTIL KDX > DEC-LEN
                ADD 1 TO NFD-COUNT
                MOVE DEC-CP(KDX) TO NFD-CP(NFD-COUNT)
            END-PERFORM
        ELSE
            ADD 1 TO NFD-COUNT
            MOVE CUR-CP TO NFD-CP(NFD-COUNT)
        END-IF
    END-IF.

REORDER-NFD.
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > NFD-COUNT
        MOVE NFD-CP(IDX) TO LOOKUP-CP
        PERFORM LOOKUP-CCC
        IF CCC-VAL = 0
            ADD 1 TO IDX
        ELSE
            MOVE IDX TO JDX
            MOVE 0 TO BREAK-FLAG
            PERFORM UNTIL JDX > NFD-COUNT OR BREAK-FLAG = 1
                MOVE NFD-CP(JDX) TO LOOKUP-CP
                PERFORM LOOKUP-CCC
                IF CCC-VAL = 0
                    MOVE 1 TO BREAK-FLAG
                ELSE
                    ADD 1 TO JDX
                END-IF
            END-PERFORM
            PERFORM SORT-RUN
            MOVE JDX TO IDX
        END-IF
    END-PERFORM.

SORT-RUN.
    MOVE IDX TO RUN-LO
    COMPUTE RUN-HI = JDX - 1
    PERFORM VARYING KDX FROM RUN-LO BY 1 UNTIL KDX > RUN-HI
        MOVE NFD-CP(KDX) TO KEY-CP
        MOVE KEY-CP TO LOOKUP-CP
        PERFORM LOOKUP-CCC
        MOVE CCC-VAL TO KEY-CCC
        MOVE KDX TO MDX
        MOVE 0 TO SORT-STOP
        PERFORM UNTIL MDX <= RUN-LO OR SORT-STOP = 1
            COMPUTE PDX = MDX - 1
            MOVE NFD-CP(PDX) TO LOOKUP-CP
            PERFORM LOOKUP-CCC
            IF CCC-VAL > KEY-CCC
                MOVE NFD-CP(PDX) TO NFD-CP(MDX)
                MOVE PDX TO MDX
            ELSE
                MOVE 1 TO SORT-STOP
            END-IF
        END-PERFORM
        MOVE KEY-CP TO NFD-CP(MDX)
    END-PERFORM.

COMPOSE-NFD.
    MOVE 0 TO NFC-COUNT
    MOVE 0 TO STARTER-IDX
    MOVE -1 TO LAST-CCC
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > NFD-COUNT
        MOVE NFD-CP(IDX) TO CUR-CP
        MOVE CUR-CP TO LOOKUP-CP
        PERFORM LOOKUP-CCC
        MOVE CCC-VAL TO CUR-CCC
        MOVE 0 TO DID-COMPOSE
        IF STARTER-IDX > 0
            MOVE NFC-CP(STARTER-IDX) TO COMP-A
            MOVE CUR-CP TO COMP-B
            PERFORM TRY-COMPOSE
            IF COMP-FOUND = 1
                IF LAST-CCC = 0 OR (CUR-CCC > 0 AND CUR-CCC > LAST-CCC)
                    MOVE COMP-RESULT TO NFC-CP(STARTER-IDX)
                    MOVE 1 TO DID-COMPOSE
                END-IF
            END-IF
        END-IF
        IF DID-COMPOSE = 0
            ADD 1 TO NFC-COUNT
            MOVE CUR-CP TO NFC-CP(NFC-COUNT)
            IF CUR-CCC = 0
                MOVE NFC-COUNT TO STARTER-IDX
                MOVE 0 TO LAST-CCC
            ELSE
                MOVE CUR-CCC TO LAST-CCC
            END-IF
        END-IF
    END-PERFORM.

TRY-COMPOSE.
    PERFORM HANGUL-COMPOSE
    IF COMP-FOUND = 0
        MOVE 0 TO TABLE-FLAG
        PERFORM LOOKUP-COMPOSE
        IF TABLE-FLAG = 1
            MOVE 1 TO COMP-FOUND
        END-IF
    END-IF.

HANGUL-COMPOSE.
    MOVE 0 TO COMP-FOUND
    IF COMP-A >= 4352 AND COMP-A < 4371 AND COMP-B >= 4449 AND COMP-B < 4470
        COMPUTE COMP-RESULT = 44032 + ((COMP-A - 4352) * 21 + (COMP-B - 4449)) * 28
        MOVE 1 TO COMP-FOUND
    ELSE
        IF COMP-A >= 44032 AND COMP-A < 55204 AND FUNCTION MOD(COMP-A - 44032, 28) = 0 AND COMP-B >= 4520 AND COMP-B < 4547
            COMPUTE COMP-RESULT = COMP-A + (COMP-B - 4519)
            MOVE 1 TO COMP-FOUND
        END-IF
    END-IF.

ADD-HIS-FINDING.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE HIS-POS TO POS-NUM
    MOVE FUNCTION TRIM(POS-NUM) TO POS-TEXT
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

ADD-ALL-POS-FINDING.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO POS-TEXT
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > CP-COUNT
        COMPUTE POS-IDX = JDX - 1
        MOVE POS-IDX TO POS-NUM
        IF JDX = 1
            STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
        ELSE
            STRING FUNCTION TRIM(POS-TEXT) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
        END-IF
    END-PERFORM
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

ADD-ZERO-WIDTH-POS-FINDING.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO POS-TEXT
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > CP-COUNT
        MOVE CP(JDX) TO LOOKUP-CP
        MOVE 0 TO TABLE-FLAG
        PERFORM IS-DEFAULT-IGNORABLE
        IF CP(JDX) = 8203 OR CP(JDX) = 8205 OR CP(JDX) = 8239 OR CP(JDX) = 8288 OR (CP(JDX) >= 65529 AND CP(JDX) <= 65531) OR (TABLE-FLAG = 1 AND NOT ((CP(JDX) >= 65024 AND CP(JDX) <= 65039) OR (CP(JDX) >= 917760 AND CP(JDX) <= 917999) OR (CP(JDX) >= 917504 AND CP(JDX) <= 917631) OR (CP(JDX) >= 8234 AND CP(JDX) <= 8238) OR (CP(JDX) >= 8294 AND CP(JDX) <= 8297)))
            COMPUTE POS-IDX = JDX - 1
            MOVE POS-IDX TO POS-NUM
            IF FUNCTION LENGTH(FUNCTION TRIM(POS-TEXT)) = 0
                STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
            ELSE
                STRING FUNCTION TRIM(POS-TEXT) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
            END-IF
        END-IF
    END-PERFORM
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

ADD-VS-POS-FINDING.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO POS-TEXT
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > CP-COUNT
        IF (CP(JDX) >= 65024 AND CP(JDX) <= 65039) OR (CP(JDX) >= 917760 AND CP(JDX) <= 917999) OR (CP(JDX) >= 6155 AND CP(JDX) <= 6157)
            COMPUTE POS-IDX = JDX - 1
            MOVE POS-IDX TO POS-NUM
            IF FUNCTION LENGTH(FUNCTION TRIM(POS-TEXT)) = 0
                STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
            ELSE
                STRING FUNCTION TRIM(POS-TEXT) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
            END-IF
        END-IF
    END-PERFORM
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

ADD-BIDI-POS-FINDING.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO POS-TEXT
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > CP-COUNT
        IF CP(JDX) = 8234 OR CP(JDX) = 8235 OR CP(JDX) = 8237 OR CP(JDX) = 8238 OR CP(JDX) = 8236 OR CP(JDX) = 8294 OR CP(JDX) = 8295 OR CP(JDX) = 8296 OR CP(JDX) = 8297
            COMPUTE POS-IDX = JDX - 1
            MOVE POS-IDX TO POS-NUM
            IF FUNCTION LENGTH(FUNCTION TRIM(POS-TEXT)) = 0
                STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
            ELSE
                STRING FUNCTION TRIM(POS-TEXT) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
            END-IF
        END-IF
    END-PERFORM
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

SCAN-AI-WATERMARK.
    PERFORM PARSE-AWD-CONTEXT
    PERFORM COLLECT-AWD-MARKERS
    PERFORM FIND-AWD-VOCAB
    COMPUTE AWD-CATEGORY =
        FUNCTION MAX(0, FUNCTION MIN(1, AWD-NNBSP-N))
        + FUNCTION MAX(0, FUNCTION MIN(1, AWD-VS-N))
        + FUNCTION MAX(0, FUNCTION MIN(1, AWD-ZWJ-N))
        + FUNCTION MAX(0, FUNCTION MIN(1, AWD-DI-N))
    COMPUTE AWD-TOTAL = AWD-NNBSP-N + AWD-VS-N + AWD-ZWJ-N + AWD-DI-N
    MOVE 0 TO AWD-DONE
    IF AWD-NNBSP-N >= 3
        PERFORM COPY-NNBSP-TO-SEL
        MOVE AW-ADV-TOL TO AWD-GAP
        PERFORM CHECK-AWD-ARITH
        IF AWD-ARITH-OK = 1
            MOVE "unicode.security.K.ai-watermark-detectability.Adversarial" TO TEMP-CODE
            PERFORM ADD-AWD-FINDING
            MOVE 1 TO AWD-DONE
        END-IF
    END-IF
    IF AWD-DONE = 0 AND AWD-ZWSP-N >= 3
        PERFORM COPY-ZWSP-TO-SEL
        MOVE AW-ZWSP-TOL TO AWD-GAP
        PERFORM CHECK-AWD-ARITH
        IF AWD-ARITH-OK = 1
            MOVE "unicode.security.K.ai-watermark-detectability.Gpt5ZwspModulo" TO TEMP-CODE
            PERFORM ADD-AWD-FINDING
            MOVE 1 TO AWD-DONE
        END-IF
    END-IF
    IF AWD-DONE = 0 AND AWD-CATEGORY >= 2
        PERFORM COPY-INVIS-TO-SEL
        MOVE "unicode.security.K.ai-watermark-detectability.Unknown" TO TEMP-CODE
        PERFORM ADD-AWD-FINDING
        MOVE 1 TO AWD-DONE
    END-IF
    IF AWD-DONE = 0 AND AWD-NNBSP-N > 0
        PERFORM COPY-NNBSP-TO-SEL
        MOVE "unicode.security.K.ai-watermark-detectability.NnbspBoundary" TO TEMP-CODE
        PERFORM ADD-AWD-FINDING
        MOVE 1 TO AWD-DONE
    END-IF
    IF AWD-DONE = 0 AND AWD-VS-N > 0
        PERFORM COPY-VS-TO-SEL
        MOVE "unicode.security.K.ai-watermark-detectability.VariationSelectorCarrier" TO TEMP-CODE
        PERFORM ADD-AWD-FINDING
        MOVE 1 TO AWD-DONE
    END-IF
    IF AWD-DONE = 0 AND AWD-ZWJ-N > 0
        PERFORM COPY-ZWJ-TO-SEL
        MOVE "unicode.security.K.ai-watermark-detectability.ZwjNonEmoji" TO TEMP-CODE
        PERFORM ADD-AWD-FINDING
        MOVE 1 TO AWD-DONE
    END-IF
    IF AWD-DONE = 0 AND AWD-CURLY-N >= 2 AND AWD-HAS-STRAIGHT = 0
        PERFORM COPY-CURLY-TO-SEL
        MOVE "unicode.security.K.ai-watermark-detectability.SmartQuoteAlternation" TO TEMP-CODE
        PERFORM ADD-AWD-FINDING
        MOVE 1 TO AWD-DONE
    END-IF
    IF AWD-DONE = 0 AND AWD-EMDASH-N >= 2 AND AWD-HAS-HYPHEN = 0
        PERFORM COPY-EMDASH-TO-SEL
        MOVE "unicode.security.K.ai-watermark-detectability.EmDashPattern" TO TEMP-CODE
        PERFORM ADD-AWD-FINDING
        MOVE 1 TO AWD-DONE
    END-IF
    IF AWD-DONE = 0 AND AWD-VOCAB-FOUND = 1
        MOVE 1 TO AWD-SEL-N
        MOVE AWD-VOCAB-POS TO AWD-SEL(1)
        MOVE "unicode.security.K.ai-watermark-detectability.StatisticalTokenChoice" TO TEMP-CODE
        PERFORM ADD-AWD-FINDING
        MOVE 1 TO AWD-DONE
    END-IF
    IF AWD-DONE = 0 AND AWD-DI-N > 0
        PERFORM COPY-DI-TO-SEL
        MOVE "unicode.security.K.ai-watermark-detectability.DefaultIgnorableCarrier" TO TEMP-CODE
        PERFORM ADD-AWD-FINDING
        MOVE 1 TO AWD-DONE
    END-IF.

PARSE-AWD-CONTEXT.
    MOVE 0 TO AW-ZWSP-TOL AW-ADV-TOL
    IF FUNCTION TRIM(ENC-ARG) NOT = " " AND FUNCTION TRIM(ENC-ARG) NOT = "-"
        COMPUTE AW-ZWSP-TOL = FUNCTION NUMVAL(ENC-ARG)
    END-IF
    IF FUNCTION TRIM(RFC-ARG) NOT = " " AND FUNCTION TRIM(RFC-ARG) NOT = "-"
        COMPUTE AW-ADV-TOL = FUNCTION NUMVAL(RFC-ARG)
    END-IF.

COLLECT-AWD-MARKERS.
    MOVE 0 TO AWD-NNBSP-N AWD-ZWSP-N AWD-VS-N AWD-ZWJ-N
    MOVE 0 TO AWD-CURLY-N AWD-EMDASH-N AWD-DI-N AWD-INVIS-N
    MOVE 0 TO AWD-HAS-STRAIGHT AWD-HAS-HYPHEN
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO CUR-CP
        COMPUTE POS-IDX = IDX - 1
        IF CUR-CP = 8239
            ADD 1 TO AWD-NNBSP-N
            MOVE POS-IDX TO AWD-NNBSP(AWD-NNBSP-N)
        END-IF
        IF CUR-CP = 8203
            ADD 1 TO AWD-ZWSP-N
            MOVE POS-IDX TO AWD-ZWSP(AWD-ZWSP-N)
        END-IF
        IF CUR-CP = 34 OR CUR-CP = 39
            MOVE 1 TO AWD-HAS-STRAIGHT
        END-IF
        IF CUR-CP = 45
            MOVE 1 TO AWD-HAS-HYPHEN
        END-IF
        IF CUR-CP = 8212
            ADD 1 TO AWD-EMDASH-N
            MOVE POS-IDX TO AWD-EMDASH(AWD-EMDASH-N)
        END-IF
        IF CUR-CP = 8216 OR CUR-CP = 8217 OR CUR-CP = 8220 OR CUR-CP = 8221
            ADD 1 TO AWD-CURLY-N
            MOVE POS-IDX TO AWD-CURLY(AWD-CURLY-N)
        END-IF
        PERFORM CLASSIFY-AWD-MARKER
    END-PERFORM.

CLASSIFY-AWD-MARKER.
    MOVE 0 TO FOUND-FLAG
    MOVE CUR-CP TO LOOKUP-CP
    PERFORM IS-DEFAULT-IGNORABLE
    MOVE TABLE-FLAG TO AWD-IS-DI
    IF (CUR-CP >= 65024 AND CUR-CP <= 65039) OR (CUR-CP >= 917760 AND CUR-CP <= 917999)
        MOVE 1 TO AWD-IS-VS
    ELSE
        MOVE 0 TO AWD-IS-VS
    END-IF
    IF CUR-CP = 8205
        MOVE 1 TO AWD-IS-ZWJ
    ELSE
        MOVE 0 TO AWD-IS-ZWJ
    END-IF
    IF CUR-CP = 8239 OR AWD-IS-VS = 1 OR AWD-IS-ZWJ = 1 OR AWD-IS-DI = 1
        ADD 1 TO AWD-INVIS-N
        MOVE POS-IDX TO AWD-INVIS(AWD-INVIS-N)
    END-IF
    IF AWD-IS-VS = 1 OR AWD-IS-ZWJ = 1
        PERFORM AWD-EMOJI-ADJACENT
        IF FOUND-FLAG = 0
            IF AWD-IS-VS = 1
                ADD 1 TO AWD-VS-N
                MOVE POS-IDX TO AWD-VS(AWD-VS-N)
            ELSE
                ADD 1 TO AWD-ZWJ-N
                MOVE POS-IDX TO AWD-ZWJ(AWD-ZWJ-N)
            END-IF
        END-IF
    END-IF
    IF AWD-IS-DI = 1 AND AWD-IS-VS = 0 AND AWD-IS-ZWJ = 0
        ADD 1 TO AWD-DI-N
        MOVE POS-IDX TO AWD-DI(AWD-DI-N)
    END-IF.

AWD-EMOJI-ADJACENT.
    MOVE 0 TO AWD-PREV-EMOJI AWD-NEXT-EMOJI
    IF IDX > 1
        MOVE CP(IDX - 1) TO LOOKUP-CP
        PERFORM IS-EMOJI
        MOVE IS-EMOJI-FLAG TO AWD-PREV-EMOJI
    END-IF
    IF IDX < CP-COUNT
        MOVE CP(IDX + 1) TO LOOKUP-CP
        PERFORM IS-EMOJI
        MOVE IS-EMOJI-FLAG TO AWD-NEXT-EMOJI
    END-IF
    IF AWD-PREV-EMOJI = 1 OR AWD-NEXT-EMOJI = 1
        MOVE 1 TO FOUND-FLAG
    ELSE
        MOVE 0 TO FOUND-FLAG
    END-IF.

CHECK-AWD-ARITH.
    MOVE 1 TO AWD-ARITH-OK
    IF AWD-SEL-N >= 2
        COMPUTE AWD-FIRST-GAP = AWD-SEL(2) - AWD-SEL(1)
        PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX >= AWD-SEL-N OR AWD-ARITH-OK = 0
            COMPUTE AWD-BYTE = AWD-SEL(JDX + 1) - AWD-SEL(JDX)
            IF NOT (AWD-BYTE <= AWD-FIRST-GAP + AWD-GAP
                    AND AWD-FIRST-GAP <= AWD-BYTE + AWD-GAP)
                MOVE 0 TO AWD-ARITH-OK
            END-IF
        END-PERFORM
    END-IF.

FIND-AWD-VOCAB.
    MOVE 0 TO AWD-VOCAB-FOUND
    PERFORM VARYING VDX FROM 1 BY 1 UNTIL VDX > 50 OR AWD-VOCAB-FOUND = 1
        MOVE VOCAB-LEN(VDX) TO PAT-LEN
        PERFORM MATCH-AWD-VOCAB
        IF AWD-MATCH = 1
            MOVE 1 TO AWD-VOCAB-FOUND
        END-IF
    END-PERFORM.

MATCH-AWD-VOCAB.
    MOVE 0 TO AWD-MATCH
    IF PAT-LEN > 0 AND PAT-LEN <= CP-COUNT
        COMPUTE AWD-MAX-START = CP-COUNT - PAT-LEN + 1
        PERFORM VARYING SDX FROM 1 BY 1 UNTIL SDX > AWD-MAX-START OR AWD-MATCH = 1
            MOVE 1 TO AWD-ALLEQ
            PERFORM VARYING KDX FROM 1 BY 1 UNTIL KDX > PAT-LEN OR AWD-ALLEQ = 0
                COMPUTE AWD-BYTE =
                    FUNCTION ORD(VOCAB-CHARS(VDX)(KDX:1)) - 1
                COMPUTE PDX = SDX + KDX - 1
                IF CP(PDX) NOT = AWD-BYTE
                    MOVE 0 TO AWD-ALLEQ
                END-IF
            END-PERFORM
            IF AWD-ALLEQ = 1
                MOVE 1 TO AWD-MATCH
                COMPUTE AWD-VOCAB-POS = SDX - 1
            END-IF
        END-PERFORM
    END-IF.

COPY-NNBSP-TO-SEL.
    MOVE AWD-NNBSP-N TO AWD-SEL-N
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-NNBSP-N
        MOVE AWD-NNBSP(JDX) TO AWD-SEL(JDX)
    END-PERFORM.

COPY-ZWSP-TO-SEL.
    MOVE AWD-ZWSP-N TO AWD-SEL-N
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-ZWSP-N
        MOVE AWD-ZWSP(JDX) TO AWD-SEL(JDX)
    END-PERFORM.

COPY-VS-TO-SEL.
    MOVE AWD-VS-N TO AWD-SEL-N
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-VS-N
        MOVE AWD-VS(JDX) TO AWD-SEL(JDX)
    END-PERFORM.

COPY-ZWJ-TO-SEL.
    MOVE AWD-ZWJ-N TO AWD-SEL-N
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-ZWJ-N
        MOVE AWD-ZWJ(JDX) TO AWD-SEL(JDX)
    END-PERFORM.

COPY-CURLY-TO-SEL.
    MOVE AWD-CURLY-N TO AWD-SEL-N
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-CURLY-N
        MOVE AWD-CURLY(JDX) TO AWD-SEL(JDX)
    END-PERFORM.

COPY-EMDASH-TO-SEL.
    MOVE AWD-EMDASH-N TO AWD-SEL-N
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-EMDASH-N
        MOVE AWD-EMDASH(JDX) TO AWD-SEL(JDX)
    END-PERFORM.

COPY-DI-TO-SEL.
    MOVE AWD-DI-N TO AWD-SEL-N
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-DI-N
        MOVE AWD-DI(JDX) TO AWD-SEL(JDX)
    END-PERFORM.

COPY-INVIS-TO-SEL.
    MOVE AWD-INVIS-N TO AWD-SEL-N
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-INVIS-N
        MOVE AWD-INVIS(JDX) TO AWD-SEL(JDX)
    END-PERFORM.

ADD-AWD-FINDING.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO POS-TEXT
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > AWD-SEL-N
        MOVE AWD-SEL(JDX) TO POS-NUM
        IF JDX = 1
            STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
        ELSE
            STRING FUNCTION TRIM(POS-TEXT) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
        END-IF
    END-PERFORM
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

IS-EMOJI.
    MOVE 0 TO IS-EMOJI-FLAG
    COPY "src/generated/is_emoji.cpy".

IS-SKIN-TONE-BASE.
*> Emoji_Modifier_Base of LOOKUP-CP, parsed from the port's own bundled
*> emoji-data.txt into is_emoji_modifier_base.cpy — the set of codepoints that
*> legitimately accept a skin-tone modifier.
    MOVE 0 TO IS-SKIN-BASE-FLAG
    COPY "src/generated/is_emoji_modifier_base.cpy".

IS-EMOJI-PRESENTATION.
*> Emoji_Presentation of LOOKUP-CP, parsed from the port's own bundled
*> emoji-data.txt into is_emoji_presentation.cpy — the codepoints that render
*> emoji-style by default and can therefore be forced to text style by U+FE0E.
    MOVE 0 TO IS-EMOJI-PRES-FLAG
    COPY "src/generated/is_emoji_presentation.cpy".

SCAN-STREAM-SAFE.
*> UAX #15 §13 Stream-Safe Text Format: a codepoint is a non-starter iff
*> its Canonical_Combining_Class is non-zero (D49). Fire StreamSafeOverrun
*> on the first maximal non-starter run whose length exceeds the limit of
*> 30; the reported position is that run's first (0-based) codepoint index.
    MOVE 0 TO SS-IN-RUN SS-RUN-LEN SS-RUN-START SS-BASE-POS SS-FIRED
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT OR SS-FIRED = 1
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM LOOKUP-CCC
        IF CCC-VAL NOT = 0
            IF SS-IN-RUN = 0
                MOVE 1 TO SS-IN-RUN
                MOVE IDX TO SS-RUN-START
                MOVE 0 TO SS-RUN-LEN
            END-IF
            ADD 1 TO SS-RUN-LEN
            IF SS-RUN-LEN > SS-LIMIT
                COMPUTE SS-BASE-POS = SS-RUN-START - 1
                MOVE 1 TO SS-FIRED
            END-IF
        ELSE
            MOVE 0 TO SS-IN-RUN
            MOVE 0 TO SS-RUN-LEN
        END-IF
    END-PERFORM
    IF SS-FIRED = 1
        MOVE "unicode.security.F.stream-safe-violation.StreamSafeOverrun" TO TEMP-CODE
        MOVE SS-BASE-POS TO POS-NUM
        MOVE FUNCTION TRIM(POS-NUM) TO POS-TEXT
        ADD 1 TO FINDING-COUNT
        MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
        MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT)
    END-IF.

SCAN-EMOJI-ZWJ.
*> UTS #51 EmojiZwjIntegrity (identity-layer detector I3). Byte-faithful
*> transliteration of the verified Rust reference `detect`: Phase 1 collects
*> ZWJ positions (0-based) and the skin-tone count; Phase 2 short-circuits
*> Clear when there is no ZWJ and at most one skin tone; Phase 3 clears any
*> exactly-registered RGI sequence; Phase 4 walks the priority ladder
*> DoubleZWJ -> NonEmojiInjection -> OverLength -> SkinToneOverflow ->
*> UnregisteredSequence. The registered set and the ZWJ alphabet are parsed
*> from the port's own bundled data/emoji-zwj-sequences.txt.
    MOVE 0 TO EZ-ZWJ-N EZ-SKIN-N EZ-DONE
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) = 8205
            ADD 1 TO EZ-ZWJ-N
            COMPUTE EZ-ZWJ(EZ-ZWJ-N) = IDX - 1
        END-IF
        IF CP(IDX) >= 127995 AND CP(IDX) <= 127999
            ADD 1 TO EZ-SKIN-N
        END-IF
    END-PERFORM
    PERFORM BUILD-SEQ-KEY
    PERFORM IS-ZWJ-REGISTERED
    MOVE TABLE-FLAG TO EZ-IS-RGI
    IF EZ-ZWJ-N = 0 AND EZ-SKIN-N <= 1
        CONTINUE
    ELSE
        IF EZ-IS-RGI = 1
            CONTINUE
        ELSE
            PERFORM EZ-LADDER
        END-IF
    END-IF.

EZ-LADDER.
*> Priority 1: ZWJ-ZWJ adjacency; report the first ZWJ of each adjacent pair.
    PERFORM EZ-COLLECT-DOUBLE
    IF EZ-POS-N > 0
        MOVE "unicode.security.I.emoji-zwj-integrity.DoubleZWJ" TO TEMP-CODE
        PERFORM EZ-ADD-FINDING
        MOVE 1 TO EZ-DONE
    END-IF
*> Priority 2: a ZWJ flanked by a non-emoji codepoint or sitting at an edge.
    IF EZ-DONE = 0
        PERFORM EZ-FIND-INJECTION
        IF EZ-INJ-FOUND = 1
            MOVE "unicode.security.I.emoji-zwj-integrity.NonEmojiInjection"
                TO TEMP-CODE
            MOVE 1 TO EZ-POS-N
            MOVE EZ-INJ-POS TO EZ-POS(1)
            PERFORM EZ-ADD-FINDING
            MOVE 1 TO EZ-DONE
        END-IF
    END-IF
*> Priority 3: the sequence is longer than the RGI cap of 16.
    IF EZ-DONE = 0
        IF CP-COUNT > 16
            MOVE "unicode.security.I.emoji-zwj-integrity.OverLength"
                TO TEMP-CODE
            MOVE 0 TO EZ-POS-N
            PERFORM EZ-ADD-FINDING
            MOVE 1 TO EZ-DONE
        END-IF
    END-IF
*> Priority 4: five or more skin-tone modifiers (family maximum is four).
    IF EZ-DONE = 0
        IF EZ-SKIN-N >= 5
            MOVE "unicode.security.I.emoji-zwj-integrity.SkinToneOverflow"
                TO TEMP-CODE
            MOVE 0 TO EZ-POS-N
            PERFORM EZ-ADD-FINDING
            MOVE 1 TO EZ-DONE
        END-IF
    END-IF
*> Priority 5: ZWJs present but the sequence is not registered.
    IF EZ-DONE = 0
        IF EZ-ZWJ-N > 0
            MOVE "unicode.security.I.emoji-zwj-integrity.UnregisteredSequence"
                TO TEMP-CODE
            MOVE EZ-ZWJ-N TO EZ-POS-N
            PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > EZ-ZWJ-N
                MOVE EZ-ZWJ(JDX) TO EZ-POS(JDX)
            END-PERFORM
            PERFORM EZ-ADD-FINDING
            MOVE 1 TO EZ-DONE
        END-IF
    END-IF.

EZ-COLLECT-DOUBLE.
    MOVE 0 TO EZ-POS-N
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF IDX < CP-COUNT
            IF CP(IDX) = 8205 AND CP(IDX + 1) = 8205
                ADD 1 TO EZ-POS-N
                COMPUTE EZ-POS(EZ-POS-N) = IDX - 1
            END-IF
        END-IF
    END-PERFORM.

EZ-FIND-INJECTION.
*> First ZWJ whose preceding or following codepoint is not in the RGI ZWJ
*> alphabet; a ZWJ at an input edge (no preceding or no following codepoint)
*> is itself an injection-class hazard.
    MOVE 0 TO EZ-INJ-FOUND
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR EZ-INJ-FOUND = 1
        IF CP(IDX) = 8205
            IF IDX = 1 OR IDX = CP-COUNT
                MOVE 1 TO EZ-INJ-FOUND
                COMPUTE EZ-INJ-POS = IDX - 1
            ELSE
                MOVE CP(IDX - 1) TO LOOKUP-CP
                PERFORM IS-ZWJ-TARGET
                MOVE TABLE-FLAG TO EZ-PREV-TARGET
                MOVE CP(IDX + 1) TO LOOKUP-CP
                PERFORM IS-ZWJ-TARGET
                MOVE TABLE-FLAG TO EZ-NEXT-TARGET
                IF EZ-PREV-TARGET = 0 OR EZ-NEXT-TARGET = 0
                    MOVE 1 TO EZ-INJ-FOUND
                    COMPUTE EZ-INJ-POS = IDX - 1
                END-IF
            END-IF
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

BUILD-SEQ-KEY.
    MOVE SPACES TO SEQ-KEY
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > CP-COUNT
        MOVE CP(JDX) TO POS-NUM
        IF JDX = 1
            STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO SEQ-KEY
        ELSE
            STRING FUNCTION TRIM(SEQ-KEY) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO SEQ-KEY
        END-IF
    END-PERFORM.

EZ-ADD-FINDING.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO POS-TEXT
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > EZ-POS-N
        MOVE EZ-POS(JDX) TO POS-NUM
        IF JDX = 1
            STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
        ELSE
            STRING FUNCTION TRIM(POS-TEXT) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
        END-IF
    END-PERFORM
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

IS-ZWJ-REGISTERED.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/zwj_registered.cpy".

IS-ZWJ-TARGET.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/zwj_alphabet.cpy".

SCAN-RENDERER-DIVERGENCE.
*> Display-layer variance detector. Byte-faithful transliteration of the
*> Rust reference security/display/renderer_divergence.rs: five variance
*> triggers tested in priority order over one input. The first trigger that
*> holds classifies the input; when none hold the input is clear (it renders
*> the same across the renderer cohort the Standard documents as stable). It
*> reuses the port's own tables only — the variation-selector ranges, the
*> GCB=Extend class from gcb_class.cpy, the registered RGI ZWJ set from
*> zwj_registered.cpy, the fullwidth/halfwidth block, and the strong-LTR /
*> strong-RTL bidi classes.
    MOVE 0 TO RD-DONE
    PERFORM RD-COUNTS
*> Priority 1: a Zalgo-style combining-mark stack of >= 4 marks on a base.
    PERFORM RD-CHECK-COMBINING-STACK
*> Priority 2: any variation selector present.
    IF RD-DONE = 0
        PERFORM RD-CHECK-VS
    END-IF
*> Priority 3: a ZWJ-containing input not in the registered RGI ZWJ set.
    IF RD-DONE = 0
        PERFORM RD-CHECK-ZWJ
    END-IF
*> Priority 4: a fullwidth/halfwidth codepoint present.
    IF RD-DONE = 0
        PERFORM RD-CHECK-FULLWIDTH
    END-IF
*> Priority 5: both strong-LTR and strong-RTL codepoints in one input.
    IF RD-DONE = 0
        PERFORM RD-CHECK-MIXED
    END-IF.

RD-COUNTS.
*> ZWJ presence plus the strong-LTR / strong-RTL tallies the mixed-direction
*> rung consults; the strong-bidi predicates are the port's own bidi tables.
    MOVE 0 TO RD-HAS-ZWJ RD-LTR-COUNT RD-RTL-COUNT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) = RD-ZWJ
            MOVE 1 TO RD-HAS-ZWJ
        END-IF
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM IS-STRONG-LTR
        IF TABLE-FLAG = 1
            ADD 1 TO RD-LTR-COUNT
        END-IF
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM IS-STRONG-RTL
        IF TABLE-FLAG = 1
            ADD 1 TO RD-RTL-COUNT
        END-IF
    END-PERFORM.

RD-CHECK-COMBINING-STACK.
*> First base codepoint (not GCB=Extend) immediately followed by exactly
*> RD-MIN-STACK consecutive GCB=Extend marks; reports the base position.
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR RD-DONE = 1
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM LOOKUP-GCB
        IF GCB-CLASS NOT = 5 AND (IDX + RD-MIN-STACK) <= CP-COUNT
            MOVE 1 TO RD-ALL-EXT
            PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > RD-MIN-STACK
                MOVE CP(IDX + JDX) TO LOOKUP-CP
                PERFORM LOOKUP-GCB
                IF GCB-CLASS NOT = 5
                    MOVE 0 TO RD-ALL-EXT
                END-IF
            END-PERFORM
            IF RD-ALL-EXT = 1
                MOVE "unicode.security.D.renderer-divergence.CombiningStackOverflow" TO TEMP-CODE
                COMPUTE RD-POS = IDX - 1
                PERFORM RD-EMIT-ONE
                MOVE 1 TO RD-DONE
            END-IF
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

RD-CHECK-VS.
*> First variation selector (FE00-FE0F, E0100-E01EF, or 180B-180D).
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR RD-DONE = 1
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM IS-VARIATION-SELECTOR
        IF TABLE-FLAG = 1
            MOVE "unicode.security.D.renderer-divergence.VariationSelectorVariance" TO TEMP-CODE
            COMPUTE RD-POS = IDX - 1
            PERFORM RD-EMIT-ONE
            MOVE 1 TO RD-DONE
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

RD-CHECK-ZWJ.
*> A ZWJ-bearing input that is not an exactly-registered RGI ZWJ sequence;
*> reports the first ZWJ. Registered sequences fall through to later rungs.
    IF RD-HAS-ZWJ = 1
        PERFORM BUILD-SEQ-KEY
        PERFORM IS-ZWJ-REGISTERED
        IF TABLE-FLAG = 0
            MOVE 1 TO IDX
            PERFORM UNTIL IDX > CP-COUNT OR RD-DONE = 1
                IF CP(IDX) = RD-ZWJ
                    MOVE "unicode.security.D.renderer-divergence.UnregisteredZwjVariance" TO TEMP-CODE
                    COMPUTE RD-POS = IDX - 1
                    PERFORM RD-EMIT-ONE
                    MOVE 1 TO RD-DONE
                END-IF
                ADD 1 TO IDX
            END-PERFORM
        END-IF
    END-IF.

RD-CHECK-FULLWIDTH.
*> First codepoint in the Halfwidth and Fullwidth Forms block FF01..FFEF.
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR RD-DONE = 1
        IF CP(IDX) >= 65281 AND CP(IDX) <= 65519
            MOVE "unicode.security.D.renderer-divergence.FullwidthVariance" TO TEMP-CODE
            COMPUTE RD-POS = IDX - 1
            PERFORM RD-EMIT-ONE
            MOVE 1 TO RD-DONE
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

RD-CHECK-MIXED.
*> Both strong-LTR and strong-RTL present; positions are intentionally empty.
    IF RD-LTR-COUNT > 0 AND RD-RTL-COUNT > 0
        MOVE "unicode.security.D.renderer-divergence.MixedDirectionVariance" TO TEMP-CODE
        ADD 1 TO FINDING-COUNT
        MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
        MOVE SPACES TO FINDING-POS(FINDING-COUNT)
        MOVE 1 TO RD-DONE
    END-IF.

RD-EMIT-ONE.
    MOVE RD-POS TO POS-NUM
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE FUNCTION TRIM(POS-NUM) TO FINDING-POS(FINDING-COUNT).

SCAN-FILENAME-DISGUISE.
*> Filename/extension disguise detector. Byte-faithful transliteration of the
*> verified Rust reference security/display/filename_disguise.rs: four disguise
*> triggers tested in priority order over one filename's codepoints. The visible
*> extension is the region after the last ASCII dot; a benign-looking name can
*> hide an executable byte extension when a bidi format-control reorders the
*> glyphs, or when the extension carries fullwidth/halfwidth or combining
*> codepoints. The first trigger that holds classifies the input; when none hold
*> the input is clear (a native-RTL name with no bidi controls clears). It reuses
*> the port's own predicates only — the bidi format-control set shared with the
*> rtl-injection and covert-display detectors, the GCB=Extend class from
*> gcb_class.cpy, and the fullwidth/halfwidth block; never a host filesystem or
*> rendering library.
    MOVE 0 TO FD-CLASS FD-DONE FD-POS
    PERFORM FD-COMPUTE-DOTS
*> Priority 1: any bidi format-control anywhere in the filename.
    PERFORM FD-CHECK-BIDI
*> Priority 2: a fullwidth/halfwidth codepoint at or after the extension start.
    IF FD-DONE = 0
        PERFORM FD-CHECK-FULLWIDTH
    END-IF
*> Priority 3: a combining (GCB=Extend) codepoint in the extension region.
    IF FD-DONE = 0
        PERFORM FD-CHECK-COMBINING
    END-IF
*> Priority 4: three or more dot separators (advisory multi-extension).
    IF FD-DONE = 0
        PERFORM FD-CHECK-MULTI
    END-IF
    PERFORM FD-EMIT.

FD-COMPUTE-DOTS.
*> Tally every ASCII dot (U+002E), remember the last one's 1-indexed position,
*> and set the extension-region start. With no dot the start is past the end so
*> the extension-scoped rungs find nothing.
    MOVE 0 TO FD-DOT-COUNT FD-LAST-DOT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF CP(IDX) = 46
            ADD 1 TO FD-DOT-COUNT
            MOVE IDX TO FD-LAST-DOT
        END-IF
    END-PERFORM
    IF FD-LAST-DOT = 0
        COMPUTE FD-EXT-START = CP-COUNT + 1
    ELSE
        COMPUTE FD-EXT-START = FD-LAST-DOT + 1
    END-IF.

FD-CHECK-BIDI.
*> First bidi format-control anywhere; reports its 0-indexed position.
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR FD-DONE = 1
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM IS-BIDI-FORMAT-CONTROL
        IF TABLE-FLAG = 1
            MOVE 1 TO FD-CLASS
            COMPUTE FD-POS = IDX - 1
            MOVE 1 TO FD-DONE
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

FD-CHECK-FULLWIDTH.
*> First codepoint in the Halfwidth and Fullwidth Forms block FF01..FFEF at or
*> after the extension start.
    MOVE FD-EXT-START TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR FD-DONE = 1
        IF CP(IDX) >= 65281 AND CP(IDX) <= 65519
            MOVE 2 TO FD-CLASS
            COMPUTE FD-POS = IDX - 1
            MOVE 1 TO FD-DONE
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

FD-CHECK-COMBINING.
*> First GCB=Extend codepoint at or after the extension start; the same GCB
*> class (5) the renderer-divergence combining-stack rung consults.
    MOVE FD-EXT-START TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR FD-DONE = 1
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM LOOKUP-GCB
        IF GCB-CLASS = 5
            MOVE 3 TO FD-CLASS
            COMPUTE FD-POS = IDX - 1
            MOVE 1 TO FD-DONE
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

FD-CHECK-MULTI.
*> Three or more dot separators; positions are all dot positions.
    IF FD-DOT-COUNT >= FD-MIN-DOTS
        MOVE 4 TO FD-CLASS
        MOVE 1 TO FD-DONE
    END-IF.

FD-EMIT.
*> Emit the reason code for the classification. Every reachable value 0..4 has
*> an explicit arm; WHEN OTHER is unreachable and signals a defect rather than
*> silently falling through.
    EVALUATE FD-CLASS
        WHEN 0
            CONTINUE
        WHEN 1
            MOVE "unicode.security.D.filename-disguise.RloFlip" TO TEMP-CODE
            PERFORM FD-EMIT-ONE
        WHEN 2
            MOVE "unicode.security.D.filename-disguise.WidthClassExt" TO TEMP-CODE
            PERFORM FD-EMIT-ONE
        WHEN 3
            MOVE "unicode.security.D.filename-disguise.CombiningInExt" TO TEMP-CODE
            PERFORM FD-EMIT-ONE
        WHEN 4
            MOVE "unicode.security.D.filename-disguise.MultipleExtensions" TO TEMP-CODE
            PERFORM FD-EMIT-DOTS
        WHEN OTHER
            DISPLAY "ERROR filename-disguise unreachable classification "
                FUNCTION TRIM(FD-CLASS)
            MOVE 1 TO RETURN-CODE
    END-EVALUATE.

FD-EMIT-ONE.
*> Single-position finding at FD-POS.
    MOVE FD-POS TO POS-NUM
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE FUNCTION TRIM(POS-NUM) TO FINDING-POS(FINDING-COUNT).

FD-EMIT-DOTS.
*> Finding whose positions are every ASCII dot in the filename, 0-indexed.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO POS-TEXT
    PERFORM VARYING JDX FROM 1 BY 1 UNTIL JDX > CP-COUNT
        IF CP(JDX) = 46
            COMPUTE POS-IDX = JDX - 1
            MOVE POS-IDX TO POS-NUM
            IF FUNCTION LENGTH(FUNCTION TRIM(POS-TEXT)) = 0
                STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
            ELSE
                STRING FUNCTION TRIM(POS-TEXT) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
            END-IF
        END-IF
    END-PERFORM
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

SCAN-IDENTIFIER-FORM-DRIFT.
*> Cross-layer identifier x form-drift detector. Byte-faithful transliteration
*> of the verified Rust reference security/boundary/identifier_form_drift.rs.
*> A two-stage validator that checks UTS #39 Identifier_Status before versus
*> after NFKD can be bypassed when a codepoint's status differs from its NFKD
*> head's: U+1D44E (Restricted) folds to 'a' (Allowed), fullwidth/circled/
*> ligature/roman-numeral forms likewise. The sole sub-threat fires on the
*> first input position whose Identifier_Status differs from that of its NFKD
*> head, and the scan tallies the total shift count. It reuses the port's own
*> UTS #39 Allowed predicate (IS-ID-ALLOWED over the bundled IdentifierStatus
*> table) and its own compatibility-decomposition plus canonical reorder to
*> obtain the NFKD head; never a host normalization or identifier library.
    MOVE 0 TO IFD-CLASS IFD-DONE IFD-POS IFD-SHIFT-COUNT
    PERFORM VARYING IFD-IDX FROM 1 BY 1 UNTIL IFD-IDX > CP-COUNT
        MOVE CP(IFD-IDX) TO LOOKUP-CP
        PERFORM IS-ID-ALLOWED
        MOVE TABLE-FLAG TO IFD-CP-ALLOWED
        MOVE CP(IFD-IDX) TO IFD-CUR-CP
        PERFORM IFD-NFKD-HEAD-ALLOWED
*> Restricted before NFKD and Allowed after: the direction an attacker gains
*> from, and the one every case this detector exists for takes. The opposite
*> direction reports all 11,172 precomposed Hangul syllables, whose head jamo
*> are Restricted, for no attacker gain.
        IF IFD-CP-ALLOWED = 0 AND IFD-HEAD-ALLOWED = 1
            ADD 1 TO IFD-SHIFT-COUNT
            IF IFD-DONE = 0
                MOVE 1 TO IFD-CLASS
                COMPUTE IFD-POS = IFD-IDX - 1
                MOVE 1 TO IFD-DONE
            END-IF
        END-IF
    END-PERFORM
    PERFORM IFD-EMIT.

IFD-NFKD-HEAD-ALLOWED.
*> Identifier_Status = Allowed of the first codepoint of IFD-CUR-CP's NFKD
*> form, or of IFD-CUR-CP itself when the decomposition is empty (defensive —
*> the compatibility decompose is total and yields at least the codepoint).
*> Builds the full NFKD run into the shared NFD scratch, canonically reorders
*> it, then reads the head. Uses the shared IDX/JDX/KDX scratch, which is why
*> the caller iterates over IFD-IDX rather than IDX.
    MOVE 0 TO NFD-COUNT
    MOVE IFD-CUR-CP TO CUR-CP
    PERFORM COMPAT-DECOMPOSE-ONE
    PERFORM REORDER-NFD
    IF NFD-COUNT = 0
        MOVE IFD-CUR-CP TO LOOKUP-CP
    ELSE
        MOVE NFD-CP(1) TO LOOKUP-CP
    END-IF
    PERFORM IS-ID-ALLOWED
    MOVE TABLE-FLAG TO IFD-HEAD-ALLOWED.

COMPAT-DECOMPOSE-ONE.
*> Append CUR-CP's full NFKD (compatibility) decomposition to the NFD scratch:
*> Hangul syllables by the algorithmic L/V/T formula (their compatibility and
*> canonical forms coincide), every other codepoint by the fully-expanded
*> nfkd_decomp table, and codepoints with no mapping as themselves.
    IF CUR-CP >= 44032 AND CUR-CP < 55204
        COMPUTE HS-INDEX = CUR-CP - 44032
        COMPUTE HL-VAL = 4352 + (HS-INDEX / 588)
        COMPUTE HV-VAL = 4449 + (FUNCTION MOD(HS-INDEX, 588) / 28)
        COMPUTE HT-INDEX = FUNCTION MOD(HS-INDEX, 28)
        ADD 1 TO NFD-COUNT
        MOVE HL-VAL TO NFD-CP(NFD-COUNT)
        ADD 1 TO NFD-COUNT
        MOVE HV-VAL TO NFD-CP(NFD-COUNT)
        IF HT-INDEX NOT = 0
            ADD 1 TO NFD-COUNT
            COMPUTE NFD-CP(NFD-COUNT) = 4519 + HT-INDEX
        END-IF
    ELSE
        MOVE CUR-CP TO LOOKUP-CP
        PERFORM LOOKUP-NFKD-DECOMP
        IF DEC-FOUND = 1
            PERFORM VARYING KDX FROM 1 BY 1 UNTIL KDX > DEC-LEN
                ADD 1 TO NFD-COUNT
                MOVE DEC-CP(KDX) TO NFD-CP(NFD-COUNT)
            END-PERFORM
        ELSE
            ADD 1 TO NFD-COUNT
            MOVE CUR-CP TO NFD-CP(NFD-COUNT)
        END-IF
    END-IF.

IFD-EMIT.
*> Emit the reason code for the classification. IFD-CLASS 0 is clear and 1 is
*> the sole sub-threat IdentifierStatusShift; WHEN OTHER is unreachable and
*> signals a defect rather than silently falling through.
    EVALUATE IFD-CLASS
        WHEN 0
            CONTINUE
        WHEN 1
            MOVE "unicode.security.X.identifier-form-drift.IdentifierStatusShift" TO TEMP-CODE
            PERFORM IFD-EMIT-ONE
        WHEN OTHER
            DISPLAY "ERROR identifier-form-drift unreachable classification "
                FUNCTION TRIM(IFD-CLASS)
            MOVE 1 TO RETURN-CODE
    END-EVALUATE.

IFD-EMIT-ONE.
*> Single-position finding at the first status-shifting codepoint.
    MOVE IFD-POS TO POS-NUM
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE FUNCTION TRIM(POS-NUM) TO FINDING-POS(FINDING-COUNT).

SCAN-WIDTH-CLASS-CONFUSION.
*> UAX #11 East Asian Width class confusion. A Fullwidth (EAW = F) or Halfwidth
*> (EAW = H) codepoint whose NFKD head carries a different width class is a
*> compatibility-fold homograph: U+FF21 'Ａ' (F) folds to U+0041 'A' (Na), and
*> U+FF71 'ｱ' (H) folds to U+30A2 'ア' (W). The two-system bypass is a
*> validator that whitelists ASCII rejecting Ａ while a downstream NFKC step
*> folds it to plain A, so ＡＤＭＩＮ claims the username ADMIN.
*>
*> Only membership is needed, not the full class: an F codepoint folds exactly
*> when its NFKD head is not F, and likewise for H. Both passes run so that a
*> Fullwidth fold takes priority over a Halfwidth one wherever each occurs,
*> matching the reference's sub-threat order. Hangul syllables decompose to
*> jamos that are still Wide, so pure Hangul stays clear.
    MOVE 0 TO WCC-CLASS WCC-POS
    MOVE 0 TO WCC-FULL-DONE WCC-HALF-DONE
    PERFORM VARYING WCC-IDX FROM 1 BY 1 UNTIL WCC-IDX > CP-COUNT
        MOVE CP(WCC-IDX) TO WCC-CUR-CP
        MOVE WCC-CUR-CP TO LOOKUP-CP
        PERFORM IS-EAW-FULLWIDTH
        MOVE TABLE-FLAG TO WCC-CP-WIDE
        IF WCC-CP-WIDE = 1 AND WCC-FULL-DONE = 0
            PERFORM WCC-NFKD-HEAD-FULLWIDTH
            IF WCC-HEAD-WIDE = 0
                COMPUTE WCC-FULL-POS = WCC-IDX - 1
                MOVE 1 TO WCC-FULL-DONE
            END-IF
        END-IF
        MOVE WCC-CUR-CP TO LOOKUP-CP
        PERFORM IS-EAW-HALFWIDTH
        MOVE TABLE-FLAG TO WCC-CP-WIDE
        IF WCC-CP-WIDE = 1 AND WCC-HALF-DONE = 0
            PERFORM WCC-NFKD-HEAD-HALFWIDTH
            IF WCC-HEAD-WIDE = 0
                COMPUTE WCC-HALF-POS = WCC-IDX - 1
                MOVE 1 TO WCC-HALF-DONE
            END-IF
        END-IF
    END-PERFORM
    IF WCC-FULL-DONE = 1
        MOVE 1 TO WCC-CLASS
        MOVE WCC-FULL-POS TO WCC-POS
    ELSE
        IF WCC-HALF-DONE = 1
            MOVE 2 TO WCC-CLASS
            MOVE WCC-HALF-POS TO WCC-POS
        END-IF
    END-IF
    PERFORM WCC-EMIT.

WCC-NFKD-HEAD-FULLWIDTH.
*> Fullwidth membership of the first codepoint of WCC-CUR-CP's NFKD form, or of
*> WCC-CUR-CP itself when the decomposition is empty (defensive — the
*> compatibility decompose is total). Builds the NFKD run into the shared NFD
*> scratch and canonically reorders it before reading the head, exactly as the
*> identifier-form-drift head lookup does.
    MOVE 0 TO NFD-COUNT
    MOVE WCC-CUR-CP TO CUR-CP
    PERFORM COMPAT-DECOMPOSE-ONE
    PERFORM REORDER-NFD
    IF NFD-COUNT = 0
        MOVE WCC-CUR-CP TO LOOKUP-CP
    ELSE
        MOVE NFD-CP(1) TO LOOKUP-CP
    END-IF
    PERFORM IS-EAW-FULLWIDTH
    MOVE TABLE-FLAG TO WCC-HEAD-WIDE.

WCC-NFKD-HEAD-HALFWIDTH.
*> Halfwidth membership of the NFKD head, mirroring WCC-NFKD-HEAD-FULLWIDTH.
    MOVE 0 TO NFD-COUNT
    MOVE WCC-CUR-CP TO CUR-CP
    PERFORM COMPAT-DECOMPOSE-ONE
    PERFORM REORDER-NFD
    IF NFD-COUNT = 0
        MOVE WCC-CUR-CP TO LOOKUP-CP
    ELSE
        MOVE NFD-CP(1) TO LOOKUP-CP
    END-IF
    PERFORM IS-EAW-HALFWIDTH
    MOVE TABLE-FLAG TO WCC-HEAD-WIDE.

WCC-EMIT.
*> Emit the reason code. WCC-CLASS 0 is clear, 1 is FullwidthFold, 2 is
*> HalfwidthFold; WHEN OTHER is unreachable and signals a defect rather than
*> silently falling through.
    EVALUATE WCC-CLASS
        WHEN 0
            CONTINUE
        WHEN 1
            MOVE "unicode.security.F.width-class-confusion.FullwidthFold" TO TEMP-CODE
            PERFORM WCC-EMIT-ONE
        WHEN 2
            MOVE "unicode.security.F.width-class-confusion.HalfwidthFold" TO TEMP-CODE
            PERFORM WCC-EMIT-ONE
        WHEN OTHER
            DISPLAY "ERROR width-class-confusion unreachable classification "
                FUNCTION TRIM(WCC-CLASS)
            MOVE 1 TO RETURN-CODE
    END-EVALUATE.

WCC-EMIT-ONE.
*> Single-position finding at the fold codepoint.
    MOVE WCC-POS TO ONE-POS
    PERFORM ADD-ONE-POS-FINDING.

ADD-ONE-POS-FINDING.
*> A finding that localises exactly one position, given in ONE-POS. The form
*> detectors report the first divergence rather than the whole span, which is
*> what the reference localises.
    MOVE ONE-POS TO POS-NUM
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE FUNCTION TRIM(POS-NUM) TO FINDING-POS(FINDING-COUNT).

ADD-NO-POS-FINDING.
*> A finding that localises nothing: the whole-sequence normalization ratios
*> implicate the input as a unit, not any one codepoint.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO FINDING-POS(FINDING-COUNT).

SCAN-ADMISSIBILITY-FORM-DRIFT.
*> Cross-layer identifier-admissibility x form-drift detector. Byte-faithful
*> transliteration of the verified Rust reference detect. The whole-string
*> UAX #31 / UTS #39 admissibility predicate IS-ALLOWED-IDENTIFIER is evaluated
*> once on the input and once on its NFKC form; the sole sub-threat
*> AdmissibilityFormDrift fires whenever the two verdicts disagree. This is the
*> string-level complement of identifier-form-drift: a decomposed Hangul jamo
*> sequence passes the per-codepoint status scan cleanly yet is rejected here,
*> because the jamo run is not an allowed identifier while its NFKC composition
*> into a precomposed syllable is. It reuses the port's own admissibility
*> predicate and its own NFKC pipeline (COMPUTE-NFKC = NFKD then canonical
*> compose); never a host normalization or identifier library. No position is
*> reported — the predicate is whole-string.
    PERFORM COMPUTE-NFKC
    MOVE CP-COUNT TO AFD-SEQ-COUNT
    PERFORM VARYING AFD-IDX FROM 1 BY 1 UNTIL AFD-IDX > CP-COUNT
        MOVE CP(AFD-IDX) TO AFD-CP(AFD-IDX)
    END-PERFORM
    PERFORM IS-ALLOWED-IDENTIFIER
    MOVE AFD-ID-RESULT TO AFD-IN-OK
    MOVE NFC-COUNT TO AFD-SEQ-COUNT
    PERFORM VARYING AFD-IDX FROM 1 BY 1 UNTIL AFD-IDX > NFC-COUNT
        MOVE NFC-CP(AFD-IDX) TO AFD-CP(AFD-IDX)
    END-PERFORM
    PERFORM IS-ALLOWED-IDENTIFIER
    MOVE AFD-ID-RESULT TO AFD-NFKC-OK
    IF AFD-IN-OK = AFD-NFKC-OK
        MOVE 0 TO AFD-CLASS
    ELSE
        MOVE 1 TO AFD-CLASS
    END-IF
    PERFORM AFD-EMIT.

IS-ALLOWED-IDENTIFIER.
*> UAX #31 whole-string default identifier AND every codepoint UTS #39 Allowed,
*> over the AFD-CP scratch (indices 1..AFD-SEQ-COUNT). Mirrors the reference
*> is_allowed_identifier = is_default_identifier ∧ all is_id_allowed. Result in
*> AFD-ID-RESULT (1 admissible, 0 not).
    PERFORM IS-DEFAULT-IDENTIFIER
    IF AFD-DEFAULT-ID = 0
        MOVE 0 TO AFD-ID-RESULT
    ELSE
        MOVE 1 TO AFD-ALL-ALLOWED
        PERFORM VARYING AFD-IDX FROM 1 BY 1
                UNTIL AFD-IDX > AFD-SEQ-COUNT OR AFD-ALL-ALLOWED = 0
            MOVE AFD-CP(AFD-IDX) TO LOOKUP-CP
            PERFORM IS-ID-ALLOWED
            IF TABLE-FLAG = 0
                MOVE 0 TO AFD-ALL-ALLOWED
            END-IF
        END-PERFORM
        MOVE AFD-ALL-ALLOWED TO AFD-ID-RESULT
    END-IF.

IS-DEFAULT-IDENTIFIER.
*> Non-empty sequence whose first codepoint is a default-id start and whose
*> remaining codepoints are all default-id continue. Result in AFD-DEFAULT-ID.
    IF AFD-SEQ-COUNT = 0
        MOVE 0 TO AFD-DEFAULT-ID
    ELSE
        MOVE AFD-CP(1) TO LOOKUP-CP
        PERFORM IS-DEFAULT-ID-START
        IF AFD-START-OK = 0
            MOVE 0 TO AFD-DEFAULT-ID
        ELSE
            MOVE 1 TO AFD-DEFAULT-ID
            PERFORM VARYING AFD-IDX FROM 2 BY 1
                    UNTIL AFD-IDX > AFD-SEQ-COUNT OR AFD-DEFAULT-ID = 0
                MOVE AFD-CP(AFD-IDX) TO LOOKUP-CP
                PERFORM IS-DEFAULT-ID-CONTINUE
                IF AFD-CONTINUE-OK = 0
                    MOVE 0 TO AFD-DEFAULT-ID
                END-IF
            END-PERFORM
        END-IF
    END-IF.

IS-DEFAULT-ID-START.
*> UAX #31 default identifier start of LOOKUP-CP: XID_Start (from the bundled
*> DerivedCoreProperties ranges) or U+005F LOW LINE. Result in AFD-START-OK.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/xid_start.cpy".
    IF TABLE-FLAG = 1 OR LOOKUP-CP = 95
        MOVE 1 TO AFD-START-OK
    ELSE
        MOVE 0 TO AFD-START-OK
    END-IF.

IS-DEFAULT-ID-CONTINUE.
*> UAX #31 default identifier continue of LOOKUP-CP: XID_Continue (from the
*> bundled DerivedCoreProperties ranges). Result in AFD-CONTINUE-OK.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/xid_continue.cpy".
    MOVE TABLE-FLAG TO AFD-CONTINUE-OK.

AFD-EMIT.
*> Emit the reason code for the classification. AFD-CLASS 0 is clear and 1 is
*> the sole sub-threat AdmissibilityFormDrift; WHEN OTHER is unreachable and
*> signals a defect rather than silently falling through.
    EVALUATE AFD-CLASS
        WHEN 0
            CONTINUE
        WHEN 1
            MOVE "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift"
                TO TEMP-CODE
            PERFORM AFD-EMIT-ONE
        WHEN OTHER
            DISPLAY "ERROR admissibility-form-drift unreachable classification "
                FUNCTION TRIM(AFD-CLASS)
            MOVE 1 TO RETURN-CODE
    END-EVALUATE.

AFD-EMIT-ONE.
*> Whole-string finding with no implicated positions (the predicate is
*> whole-string), so FINDING-POS is left empty.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO FINDING-POS(FINDING-COUNT).

SCAN-SOURCE-DISPLAY-DIVERGENCE.
*> Source-display divergence (Tier D1 aggregator). Byte-faithful transliteration
*> of the verified Rust reference `detect`: what a reviewer sees differs from what
*> the machine runs. It runs the port's own five constituent detectors over the
*> same codepoint stream, in the canonical aggregation order tag-block ->
*> variation-selector -> zero-width -> bidi-control -> homoglyph, and counts how
*> many fire (fire = the constituent produced a finding, i.e. its classification
*> is not Clear). Zero fires -> clear; exactly one -> pass through that family's
*> tag; two or more -> Compound. Each constituent is run in isolation by zeroing
*> FINDING-COUNT around it and reading the count it leaves; its per-family
*> findings are discarded so only the aggregator's single verdict remains. This
*> reuses DETECT-TAG-BLOCK, DETECT-VARIATION, DETECT-ZERO-WIDTH, DETECT-BIDI and
*> DETECT-HOMOGLYPH — no new predicate, table or normalization. No position is
*> reported at this layer.
    MOVE 0 TO SDD-FIRED-COUNT
    MOVE SPACES TO SDD-TAG
    MOVE FINDING-COUNT TO SDD-SAVED-COUNT
    PERFORM DETECT-TAG-BLOCK
    IF FINDING-COUNT > SDD-SAVED-COUNT
        ADD 1 TO SDD-FIRED-COUNT
        MOVE "TagBlock" TO SDD-TAG
    END-IF
    MOVE SDD-SAVED-COUNT TO FINDING-COUNT
    PERFORM DETECT-VARIATION
    IF FINDING-COUNT > SDD-SAVED-COUNT
        ADD 1 TO SDD-FIRED-COUNT
        MOVE "VariationSelector" TO SDD-TAG
    END-IF
    MOVE SDD-SAVED-COUNT TO FINDING-COUNT
    PERFORM DETECT-ZERO-WIDTH
    IF FINDING-COUNT > SDD-SAVED-COUNT
        ADD 1 TO SDD-FIRED-COUNT
        MOVE "ZeroWidth" TO SDD-TAG
    END-IF
    MOVE SDD-SAVED-COUNT TO FINDING-COUNT
*> Presence, not balance. A Trojan Source payload balances its controls, since
*> an unbalanced run breaks the file it hides in, so the balance verdict
*> DETECT-BIDI reports is blind to the shape the attack takes. The full format
*> control set is consulted: embeddings U+202A..U+202E and isolates
*> U+2066..U+2069.
    MOVE 0 TO SDD-BIDI-PRESENT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        IF (CP(IDX) >= 8234 AND CP(IDX) <= 8238)
           OR (CP(IDX) >= 8294 AND CP(IDX) <= 8297)
            MOVE 1 TO SDD-BIDI-PRESENT
        END-IF
    END-PERFORM
    IF SDD-BIDI-PRESENT = 1
        ADD 1 TO SDD-FIRED-COUNT
        MOVE "BidiControl" TO SDD-TAG
    END-IF
    MOVE SDD-SAVED-COUNT TO FINDING-COUNT
    PERFORM DETECT-HOMOGLYPH
*> The reference runs one homoglyph detector whose priority ladder ends in a
*> CrossScriptMix branch, so a cross-script identifier fires it. This port
*> splits that ladder and reports the script mix under mixed-script-
*> admissibility, so the constituent consults both or it misses every input
*> whose only homoglyph signal is the script mix.
    PERFORM DETECT-MIXED-SCRIPT
    IF FINDING-COUNT > SDD-SAVED-COUNT
        ADD 1 TO SDD-FIRED-COUNT
        MOVE "IdentifierHomoglyph" TO SDD-TAG
    END-IF
    MOVE SDD-SAVED-COUNT TO FINDING-COUNT
    IF SDD-FIRED-COUNT >= 2
        MOVE "Compound" TO SDD-TAG
    END-IF
    PERFORM SDD-EMIT.

SDD-EMIT.
*> Resolve the aggregated sub-threat tag to its reason code. SPACES is clear
*> (no finding); each named tag maps to unicode.security.D.source-display-
*> divergence.<Tag>. WHEN OTHER is unreachable and signals a defect rather than
*> silently falling through.
    EVALUATE SDD-TAG
        WHEN SPACES
            CONTINUE
        WHEN "TagBlock"
            MOVE "unicode.security.D.source-display-divergence.TagBlock"
                TO TEMP-CODE
            PERFORM SDD-EMIT-ONE
        WHEN "VariationSelector"
            MOVE "unicode.security.D.source-display-divergence.VariationSelector"
                TO TEMP-CODE
            PERFORM SDD-EMIT-ONE
        WHEN "ZeroWidth"
            MOVE "unicode.security.D.source-display-divergence.ZeroWidth"
                TO TEMP-CODE
            PERFORM SDD-EMIT-ONE
        WHEN "BidiControl"
            MOVE "unicode.security.D.source-display-divergence.BidiControl"
                TO TEMP-CODE
            PERFORM SDD-EMIT-ONE
        WHEN "IdentifierHomoglyph"
            MOVE "unicode.security.D.source-display-divergence.IdentifierHomoglyph"
                TO TEMP-CODE
            PERFORM SDD-EMIT-ONE
        WHEN "Compound"
            MOVE "unicode.security.D.source-display-divergence.Compound"
                TO TEMP-CODE
            PERFORM SDD-EMIT-ONE
        WHEN OTHER
            DISPLAY "ERROR source-display-divergence unreachable tag "
                FUNCTION TRIM(SDD-TAG)
            MOVE 1 TO RETURN-CODE
    END-EVALUATE.

SDD-EMIT-ONE.
*> Whole-string finding with no implicated positions (the aggregate layer reports
*> only the sub-threat; the per-family verdicts carry positions), so FINDING-POS
*> is left empty.
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO FINDING-POS(FINDING-COUNT).

SCAN-SKIN-TONE-VARIATION-FORGERY.
*> UTS #51 SkinToneVariationForgery (identity-layer detector). Byte-faithful
*> transliteration of the verified Rust reference `detect`: skin-tone-modifier
*> and variation-selector abuse on emoji bases. An adversary places a skin-tone
*> modifier on a codepoint that does not bear Emoji_Modifier_Base, stacks two
*> skin tones on one base, or forces a text-style render on an emoji-default
*> codepoint via U+FE0E. The first trigger that holds classifies the input; the
*> priority ladder is StackedSkinTones -> InvalidSkinToneTarget -> ForcedTextStyle,
*> else Clear. It reuses the port's own predicates only — the skin-tone modifier
*> block U+1F3FB..U+1F3FF shared with the emoji-zwj scan, and the Emoji_Modifier_Base
*> plus Emoji_Presentation sets parsed from the port's own bundled emoji-data.txt;
*> never a host emoji library.
    MOVE 0 TO STV-CLASS STV-DONE STV-BASE-POS STV-POS STV-MOD1 STV-MOD2
*> Priority 1: a base immediately followed by two stacked skin-tone modifiers.
    PERFORM STV-CHECK-STACKED
*> Priority 2: a skin-tone modifier on a non-Emoji_Modifier_Base codepoint.
    IF STV-DONE = 0
        PERFORM STV-CHECK-INVALID-TARGET
    END-IF
*> Priority 3: U+FE0E (VS15) forcing text style on an Emoji_Presentation codepoint.
    IF STV-DONE = 0
        PERFORM STV-CHECK-FORCED-TEXT
    END-IF
    PERFORM STV-EMIT.

STV-CHECK-STACKED.
*> First position whose next two codepoints are both skin-tone modifiers
*> (U+1F3FB..U+1F3FF); reports its 0-indexed base position and the two modifiers.
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR STV-DONE = 1
        IF IDX + 2 <= CP-COUNT
            IF (CP(IDX + 1) >= 127995 AND CP(IDX + 1) <= 127999)
                AND (CP(IDX + 2) >= 127995 AND CP(IDX + 2) <= 127999)
                COMPUTE STV-BASE-POS = IDX - 1
                MOVE CP(IDX + 1) TO STV-MOD1
                MOVE CP(IDX + 2) TO STV-MOD2
                MOVE 1 TO STV-CLASS
                MOVE 1 TO STV-DONE
            END-IF
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

STV-CHECK-INVALID-TARGET.
*> First pair (i, i+1) whose i+1 is a skin-tone modifier and whose base i does
*> NOT bear Emoji_Modifier_Base; the implicated position is the modifier's (i+1).
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR STV-DONE = 1
        IF IDX + 1 <= CP-COUNT
            IF CP(IDX + 1) >= 127995 AND CP(IDX + 1) <= 127999
                MOVE CP(IDX) TO LOOKUP-CP
                PERFORM IS-SKIN-TONE-BASE
                IF IS-SKIN-BASE-FLAG = 0
                    COMPUTE STV-BASE-POS = IDX - 1
                    MOVE 2 TO STV-CLASS
                    MOVE IDX TO STV-POS
                    MOVE 1 TO STV-DONE
                END-IF
            END-IF
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

STV-CHECK-FORCED-TEXT.
*> First pair (i, i+1) whose i+1 is U+FE0E (VS15) and whose base i has
*> Emoji_Presentation; the implicated position is the selector's (i+1).
    MOVE 1 TO IDX
    PERFORM UNTIL IDX > CP-COUNT OR STV-DONE = 1
        IF IDX + 1 <= CP-COUNT
            IF CP(IDX + 1) = 65038
                MOVE CP(IDX) TO LOOKUP-CP
                PERFORM IS-EMOJI-PRESENTATION
                IF IS-EMOJI-PRES-FLAG = 1
                    COMPUTE STV-BASE-POS = IDX - 1
                    MOVE 3 TO STV-CLASS
                    MOVE IDX TO STV-POS
                    MOVE 1 TO STV-DONE
                END-IF
            END-IF
        END-IF
        ADD 1 TO IDX
    END-PERFORM.

STV-EMIT.
*> Emit the reason code for the classification. Every reachable value 0..3 has
*> an explicit arm; WHEN OTHER is unreachable and signals a defect rather than
*> silently falling through.
    EVALUATE STV-CLASS
        WHEN 0
            CONTINUE
        WHEN 1
            MOVE "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones" TO TEMP-CODE
            PERFORM STV-EMIT-STACKED
        WHEN 2
            MOVE "unicode.security.I.skin-tone-variation-forgery.InvalidSkinToneTarget" TO TEMP-CODE
            PERFORM STV-EMIT-ONE
        WHEN 3
            MOVE "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle" TO TEMP-CODE
            PERFORM STV-EMIT-ONE
        WHEN OTHER
            DISPLAY "ERROR skin-tone-variation-forgery unreachable classification "
                FUNCTION TRIM(STV-CLASS)
            MOVE 1 TO RETURN-CODE
    END-EVALUATE.

STV-EMIT-ONE.
*> Single-position finding at STV-POS (the implicated 0-indexed position).
    MOVE STV-POS TO POS-NUM
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE FUNCTION TRIM(POS-NUM) TO FINDING-POS(FINDING-COUNT).

STV-EMIT-STACKED.
*> Finding whose positions are the two stacked skin-tone modifiers, 0-indexed:
*> [base+1, base+2].
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE SPACES TO POS-TEXT
    COMPUTE POS-IDX = STV-BASE-POS + 1
    MOVE POS-IDX TO POS-NUM
    STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
    COMPUTE POS-IDX = STV-BASE-POS + 2
    MOVE POS-IDX TO POS-NUM
    STRING FUNCTION TRIM(POS-TEXT) DELIMITED BY SIZE "," DELIMITED BY SIZE FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO POS-TEXT
    MOVE POS-TEXT TO FINDING-POS(FINDING-COUNT).

SCAN-CASE-EXPANSION-MISMATCH.
*> CaseExpansionMismatch (form-layer detector). Byte-faithful transliteration of
*> the verified Rust reference security/form/case_expansion_mismatch.rs. An
*> attacker submits text whose default-locale UAX #21 case mapping changes the
*> codepoint count: a receiver that fixes a column width and stores toUpper of a
*> username overflows on "ß" (1 in, "SS" 2 out), and one that checks equal length
*> rejects valid case-insensitive logins whose names expand under folding. At each
*> position it builds the surrounding context (rev_prefix = the earlier codepoints
*> nearest-first, suffix = the later ones) and calls the port's own context-
*> sensitive UPPER-CODEPOINT / LOWER-CODEPOINT, firing UpperExpansion (priority 1)
*> at the first position whose uppercase mapping yields more than one codepoint,
*> else LowerExpansion at the first whose lowercase mapping expands, else Clear.
*> It reuses the port's own UAX #21 case mapping (the generated SpecialCasing rows
*> plus simple mappings, selected by evaluating the context conditions); never a
*> host casing library.
    MOVE 0 TO CE-CLASS CE-UPPER-FOUND CE-LOWER-FOUND CE-POS
    MOVE 0 TO CE-UPPER-POS CE-LOWER-POS
    MOVE 0 TO CE-UPPER-COUNT CE-LOWER-COUNT CE-MAX-LEN
    MOVE 0 TO SC-LOCALE
*> One pass gathers the verdict projection: per-direction expansion counts, the
*> first expanding position in each direction, and the maximum mapped length.
    PERFORM VARYING CE-IDX FROM 1 BY 1 UNTIL CE-IDX > CP-COUNT
        PERFORM COMPUTE-CASE-CONTEXT
        PERFORM UPPER-CODEPOINT
        PERFORM LOWER-CODEPOINT
        IF UC-LEN > 1
            ADD 1 TO CE-UPPER-COUNT
            IF CE-UPPER-FOUND = 0
                COMPUTE CE-UPPER-POS = CE-IDX - 1
                MOVE 1 TO CE-UPPER-FOUND
            END-IF
        END-IF
        IF LC-LEN > 1
            ADD 1 TO CE-LOWER-COUNT
            IF CE-LOWER-FOUND = 0
                COMPUTE CE-LOWER-POS = CE-IDX - 1
                MOVE 1 TO CE-LOWER-FOUND
            END-IF
        END-IF
        IF UC-LEN > LC-LEN
            IF UC-LEN > CE-MAX-LEN
                MOVE UC-LEN TO CE-MAX-LEN
            END-IF
        ELSE
            IF LC-LEN > CE-MAX-LEN
                MOVE LC-LEN TO CE-MAX-LEN
            END-IF
        END-IF
    END-PERFORM
*> Priority: an uppercase expansion anywhere outranks a lowercase one.
    IF CE-UPPER-FOUND = 1
        MOVE 1 TO CE-CLASS
        MOVE CE-UPPER-POS TO CE-POS
    ELSE
        IF CE-LOWER-FOUND = 1
            MOVE 2 TO CE-CLASS
            MOVE CE-LOWER-POS TO CE-POS
        END-IF
    END-IF
    PERFORM CE-EMIT.

CE-EMIT.
*> Emit the reason code for the classification. Values 0 (Clear), 1
*> (UpperExpansion), and 2 (LowerExpansion) each have an explicit arm; WHEN OTHER
*> is unreachable and signals a defect rather than silently falling through.
    EVALUATE CE-CLASS
        WHEN 0
            CONTINUE
        WHEN 1
            MOVE "unicode.security.F.case-expansion-mismatch.UpperExpansion" TO TEMP-CODE
            PERFORM CE-EMIT-ONE
        WHEN 2
            MOVE "unicode.security.F.case-expansion-mismatch.LowerExpansion" TO TEMP-CODE
            PERFORM CE-EMIT-ONE
        WHEN OTHER
            DISPLAY "ERROR case-expansion-mismatch unreachable classification "
                FUNCTION TRIM(CE-CLASS)
            MOVE 1 TO RETURN-CODE
    END-EVALUATE.

CE-EMIT-ONE.
*> Single-position finding at CE-POS (the first expanding position, 0-indexed).
    MOVE CE-POS TO POS-NUM
    ADD 1 TO FINDING-COUNT
    MOVE TEMP-CODE TO FINDING-CODE(FINDING-COUNT)
    MOVE FUNCTION TRIM(POS-NUM) TO FINDING-POS(FINDING-COUNT).

UPPER-CODEPOINT.
*> upper_codepoint(SC-LOCALE, rev_prefix, suffix, cp): the matched SpecialCasing
*> row's uppercase column, else the simple uppercase mapping. Returns the actual
*> mapped sequence in UC-CP(1..UC-LEN). Assumes COMPUTE-CASE-CONTEXT has set the
*> context flags for position CE-IDX.
    MOVE CP(CE-IDX) TO LOOKUP-CP
    PERFORM FIND-SPECIAL-ROW
    IF SC-FOUND = 1
        MOVE SC-UPPER-LEN TO UC-LEN
        PERFORM VARYING SC-COPY-IDX FROM 1 BY 1 UNTIL SC-COPY-IDX > SC-UPPER-LEN
            MOVE SC-UPPER (SC-COPY-IDX) TO UC-CP (SC-COPY-IDX)
        END-PERFORM
    ELSE
        MOVE CP(CE-IDX) TO LOOKUP-CP
        PERFORM LOOKUP-SIMPLE-UPPER
        MOVE 1 TO UC-LEN
        MOVE SC-SIMPLE-UP TO UC-CP (1)
    END-IF.

LOWER-CODEPOINT.
*> lower_codepoint(SC-LOCALE, rev_prefix, suffix, cp): the matched SpecialCasing
*> row's lowercase column, else the simple lowercase mapping. Returns the actual
*> mapped sequence in LC-CP(1..LC-LEN).
    MOVE CP(CE-IDX) TO LOOKUP-CP
    PERFORM FIND-SPECIAL-ROW
    IF SC-FOUND = 1
        MOVE SC-LOWER-LEN TO LC-LEN
        PERFORM VARYING SC-COPY-IDX FROM 1 BY 1 UNTIL SC-COPY-IDX > SC-LOWER-LEN
            MOVE SC-LOWER (SC-COPY-IDX) TO LC-CP (SC-COPY-IDX)
        END-PERFORM
    ELSE
        MOVE CP(CE-IDX) TO LOOKUP-CP
        PERFORM LOOKUP-SIMPLE-LOWER
        MOVE 1 TO LC-LEN
        MOVE SC-SIMPLE-LO TO LC-CP (1)
    END-IF.

FIND-SPECIAL-ROW.
*> find_special_row(SC-LOCALE, rev_prefix, suffix, cp): scan LOOKUP-CP's
*> SpecialCasing rows (conditional rows first, in file order, then the
*> unconditional one) and select the first whose conditions hold under the current
*> locale and context flags, filling SC-UPPER / SC-LOWER. SC-FOUND stays 0 when
*> the codepoint has no SpecialCasing entry.
    MOVE 0 TO SC-FOUND
    MOVE 0 TO SC-UPPER-LEN SC-LOWER-LEN
    COPY "src/generated/special_casing.cpy".

LOOKUP-SIMPLE-UPPER.
*> Simple (single-codepoint) uppercase mapping of LOOKUP-CP from the bundled
*> UnicodeData; identity when the codepoint carries no mapping.
    MOVE LOOKUP-CP TO SC-SIMPLE-UP
    COPY "src/generated/simple_upper.cpy".

LOOKUP-SIMPLE-LOWER.
*> Simple (single-codepoint) lowercase mapping of LOOKUP-CP from the bundled
*> UnicodeData; identity when the codepoint carries no mapping.
    MOVE LOOKUP-CP TO SC-SIMPLE-LO
    COPY "src/generated/simple_lower.cpy".

IS-CASED.
*> UCD Cased membership of LOOKUP-CP, from the bundled DerivedCoreProperties.
    MOVE 0 TO SC-CASED
    COPY "src/generated/cased.cpy".

IS-SOFT-DOTTED.
*> UCD Soft_Dotted membership of LOOKUP-CP. DerivedCoreProperties carries no
*> Soft_Dotted ranges in the bundled UCD, so this set is empty — matching the
*> Rust reference, whose Soft_Dotted table is likewise empty on this data.
    MOVE 0 TO SC-SOFT-DOTTED
    COPY "src/generated/soft_dotted.cpy".

COMPUTE-CASE-CONTEXT.
*> The five UAX #21 context predicate flags at position CE-IDX, evaluated over
*> rev_prefix = input[0..CE-IDX-1] nearest-first and suffix = input[CE-IDX+1..].
    PERFORM CTX-FINAL-SIGMA
    PERFORM CTX-AFTER-SOFT-DOTTED
    PERFORM CTX-AFTER-I
    PERFORM CTX-MORE-ABOVE
    PERFORM CTX-BEFORE-DOT.

CTX-FINAL-SIGMA.
*> Final_Sigma: a cased codepoint precedes (has_cased_before) and none follows
*> before the next boundary (not has_cased_after).
    PERFORM CTX-HAS-CASED-BEFORE
    PERFORM CTX-HAS-CASED-AFTER
    IF SC-HAS-CASED-BEFORE = 1 AND SC-HAS-CASED-AFTER = 0
        MOVE 1 TO SC-FINAL-SIGMA
    ELSE
        MOVE 0 TO SC-FINAL-SIGMA
    END-IF.

CTX-HAS-CASED-BEFORE.
*> Walk rev_prefix nearest-first: a Cased codepoint before the first ccc = 0
*> boundary sets the flag.
    MOVE 0 TO SC-HAS-CASED-BEFORE SC-SCAN-STOP
    COMPUTE SC-SCAN-IDX = CE-IDX - 1
    PERFORM UNTIL SC-SCAN-IDX < 1 OR SC-SCAN-STOP = 1
        MOVE CP(SC-SCAN-IDX) TO LOOKUP-CP
        PERFORM IS-CASED
        IF SC-CASED = 1
            MOVE 1 TO SC-HAS-CASED-BEFORE
            MOVE 1 TO SC-SCAN-STOP
        ELSE
            PERFORM LOOKUP-CCC
            IF CCC-VAL = 0
                MOVE 1 TO SC-SCAN-STOP
            END-IF
        END-IF
        SUBTRACT 1 FROM SC-SCAN-IDX
    END-PERFORM.

CTX-HAS-CASED-AFTER.
*> Walk suffix forward: a Cased codepoint before the first ccc = 0 boundary sets
*> the flag.
    MOVE 0 TO SC-HAS-CASED-AFTER SC-SCAN-STOP
    COMPUTE SC-SCAN-IDX = CE-IDX + 1
    PERFORM UNTIL SC-SCAN-IDX > CP-COUNT OR SC-SCAN-STOP = 1
        MOVE CP(SC-SCAN-IDX) TO LOOKUP-CP
        PERFORM IS-CASED
        IF SC-CASED = 1
            MOVE 1 TO SC-HAS-CASED-AFTER
            MOVE 1 TO SC-SCAN-STOP
        ELSE
            PERFORM LOOKUP-CCC
            IF CCC-VAL = 0
                MOVE 1 TO SC-SCAN-STOP
            END-IF
        END-IF
        ADD 1 TO SC-SCAN-IDX
    END-PERFORM.

CTX-AFTER-SOFT-DOTTED.
*> After_Soft_Dotted: a Soft_Dotted codepoint in rev_prefix before the first
*> ccc in {0, 230} boundary.
    MOVE 0 TO SC-AFTER-SOFT-DOTTED SC-SCAN-STOP
    COMPUTE SC-SCAN-IDX = CE-IDX - 1
    PERFORM UNTIL SC-SCAN-IDX < 1 OR SC-SCAN-STOP = 1
        MOVE CP(SC-SCAN-IDX) TO LOOKUP-CP
        PERFORM IS-SOFT-DOTTED
        IF SC-SOFT-DOTTED = 1
            MOVE 1 TO SC-AFTER-SOFT-DOTTED
            MOVE 1 TO SC-SCAN-STOP
        ELSE
            PERFORM LOOKUP-CCC
            IF CCC-VAL = 0 OR CCC-VAL = 230
                MOVE 1 TO SC-SCAN-STOP
            END-IF
        END-IF
        SUBTRACT 1 FROM SC-SCAN-IDX
    END-PERFORM.

CTX-AFTER-I.
*> After_I: U+0049 (LATIN CAPITAL LETTER I) in rev_prefix before the first ccc in
*> {0, 230} boundary.
    MOVE 0 TO SC-AFTER-I SC-SCAN-STOP
    COMPUTE SC-SCAN-IDX = CE-IDX - 1
    PERFORM UNTIL SC-SCAN-IDX < 1 OR SC-SCAN-STOP = 1
        IF CP(SC-SCAN-IDX) = 73
            MOVE 1 TO SC-AFTER-I
            MOVE 1 TO SC-SCAN-STOP
        ELSE
            MOVE CP(SC-SCAN-IDX) TO LOOKUP-CP
            PERFORM LOOKUP-CCC
            IF CCC-VAL = 0 OR CCC-VAL = 230
                MOVE 1 TO SC-SCAN-STOP
            END-IF
        END-IF
        SUBTRACT 1 FROM SC-SCAN-IDX
    END-PERFORM.

CTX-MORE-ABOVE.
*> More_Above: a ccc = 230 mark in suffix before the first ccc = 0 boundary.
    MOVE 0 TO SC-MORE-ABOVE SC-SCAN-STOP
    COMPUTE SC-SCAN-IDX = CE-IDX + 1
    PERFORM UNTIL SC-SCAN-IDX > CP-COUNT OR SC-SCAN-STOP = 1
        MOVE CP(SC-SCAN-IDX) TO LOOKUP-CP
        PERFORM LOOKUP-CCC
        IF CCC-VAL = 230
            MOVE 1 TO SC-MORE-ABOVE
            MOVE 1 TO SC-SCAN-STOP
        ELSE
            IF CCC-VAL = 0
                MOVE 1 TO SC-SCAN-STOP
            END-IF
        END-IF
        ADD 1 TO SC-SCAN-IDX
    END-PERFORM.

CTX-BEFORE-DOT.
*> Before_Dot (the base term of Not_Before_Dot): U+0307 in suffix before the
*> first ccc = 0 boundary.
    MOVE 0 TO SC-BEFORE-DOT SC-SCAN-STOP
    COMPUTE SC-SCAN-IDX = CE-IDX + 1
    PERFORM UNTIL SC-SCAN-IDX > CP-COUNT OR SC-SCAN-STOP = 1
        IF CP(SC-SCAN-IDX) = 775
            MOVE 1 TO SC-BEFORE-DOT
            MOVE 1 TO SC-SCAN-STOP
        ELSE
            MOVE CP(SC-SCAN-IDX) TO LOOKUP-CP
            PERFORM LOOKUP-CCC
            IF CCC-VAL = 0
                MOVE 1 TO SC-SCAN-STOP
            END-IF
        END-IF
        ADD 1 TO SC-SCAN-IDX
    END-PERFORM.

IS-BIDI-FORMAT-CONTROL.
*> The port's own bidi format-control set — LRE/RLE/PDF/LRO/RLO and the four
*> isolate controls LRI/RLI/FSI/PDI — the same nine codepoints the
*> rtl-injection and covert-display detectors test.
    MOVE 0 TO TABLE-FLAG
    IF LOOKUP-CP = 8234 OR LOOKUP-CP = 8235 OR LOOKUP-CP = 8236 OR LOOKUP-CP = 8237 OR LOOKUP-CP = 8238 OR LOOKUP-CP = 8294 OR LOOKUP-CP = 8295 OR LOOKUP-CP = 8296 OR LOOKUP-CP = 8297
        MOVE 1 TO TABLE-FLAG
    END-IF.

IS-VARIATION-SELECTOR.
*> The port's own variation-selector ranges, shared with DETECT-VARIATION.
    MOVE 0 TO TABLE-FLAG
    IF (LOOKUP-CP >= 65024 AND LOOKUP-CP <= 65039) OR (LOOKUP-CP >= 917760 AND LOOKUP-CP <= 917999) OR (LOOKUP-CP >= 6155 AND LOOKUP-CP <= 6157)
        MOVE 1 TO TABLE-FLAG
    END-IF.

IS-STRONG-LTR.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/strong_ltr.cpy".

SELECT-ACTION.
    MOVE 0 TO BLOCKING-FLAG
    IF FINDING-COUNT = 0
        MOVE "allow" TO ACTION-NAME
    ELSE
        IF MODE-NAME = "observe" OR MODE-NAME = "warn"
            MOVE "observe" TO ACTION-NAME
        ELSE
            IF MODE-NAME = "strict"
                MOVE "reject" TO ACTION-NAME
            ELSE
                PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > FINDING-COUNT
                    IF PROFILE-NAME = "display-name" OR PROFILE-NAME = "chat-message"
                        IF FINDING-CODE(IDX)(1:36) = "unicode.security.C.malformed-utf8." OR FINDING-CODE(IDX)(1:39) = "unicode.security.C.bidi-control-balance" OR FINDING-CODE(IDX)(1:40) = "unicode.security.C.noncharacter-control"
                            MOVE 1 TO BLOCKING-FLAG
                        END-IF
                    ELSE
                        MOVE 1 TO BLOCKING-FLAG
                    END-IF
                END-PERFORM
                IF BLOCKING-FLAG = 0
                    MOVE "allow" TO ACTION-NAME
                ELSE
                    IF PROFILE-NAME = "username" OR PROFILE-NAME = "display-name" OR PROFILE-NAME = "chat-message"
                        MOVE "quarantine" TO ACTION-NAME
                    ELSE
                        MOVE "reject" TO ACTION-NAME
                    END-IF
                END-IF
            END-IF
        END-IF
    END-IF.

IS-LEGAL-VARIATION.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/legal_variation.cpy".

IS-CONFUSABLE-SOURCE.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/confusable_source.cpy".

APPLY-SCRIPT-FLAGS.
    COPY "src/generated/script_flags.cpy".

IS-STRONG-RTL.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/strong_rtl.cpy".

IS-EAW-FULLWIDTH.
*> East_Asian_Width = F. Absence from the table is the file's own @missing
*> declaration of N over the whole codepoint space, not a fallback.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/eaw_fullwidth.cpy".

IS-EAW-HALFWIDTH.
*> East_Asian_Width = H, the mirror of IS-EAW-FULLWIDTH.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/eaw_halfwidth.cpy".

IS-DEFAULT-IGNORABLE.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/default_ignorable.cpy".

IS-BIP39-WORD.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/bip39_words.cpy".

LOOKUP-CCC.
    MOVE 0 TO CCC-VAL
    COPY "src/generated/ccc_class.cpy".

LOOKUP-CANON-DECOMP.
    MOVE 0 TO DEC-FOUND
    COPY "src/generated/canonical_decomp.cpy".

LOOKUP-NFKD-DECOMP.
*> Fully-expanded compatibility (NFKD) decomposition of LOOKUP-CP, generated
*> from the bundled UnicodeData decomposition mappings.
    MOVE 0 TO DEC-FOUND
    COPY "src/generated/nfkd_decomp.cpy".

IS-ID-ALLOWED.
*> UTS #39 Identifier_Status = Allowed membership from the bundled
*> IdentifierStatus table; every codepoint outside the Allowed ranges is
*> Restricted. Shared with the mixed-script and confusable identity checks.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/id_allowed.cpy".

LOOKUP-COMPOSE.
    MOVE 0 TO TABLE-FLAG
    COPY "src/generated/canonical_compose.cpy".

LOOKUP-GCB.
    MOVE 0 TO GCB-CLASS
    COPY "src/generated/gcb_class.cpy".

LOOKUP-INCB.
    MOVE 0 TO INCB-CLASS
    COPY "src/generated/incb_class.cpy".

LOOKUP-EXTPICT.
    MOVE 0 TO IS-EP-FLAG
    COPY "src/generated/extpict.cpy".

EMIT-BLOB.
    IF FINDING-COUNT = 0
        MOVE "valid" TO VALID-TEXT
    ELSE
        MOVE "invalid" TO VALID-TEXT
    END-IF
    IF OP-NAME = "is-utf8-blob"
        DISPLAY "BLOB " FUNCTION TRIM(VALID-TEXT)
    ELSE
        DISPLAY "VALIDATE " FUNCTION TRIM(VALID-TEXT)
        IF FINDING-COUNT = 0
            DISPLAY "BYTES " WITH NO ADVANCING
            PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
                MOVE CP(IDX) TO POS-NUM
                IF IDX > 1
                    DISPLAY "," WITH NO ADVANCING
                END-IF
                DISPLAY FUNCTION TRIM(POS-NUM) WITH NO ADVANCING
            END-PERFORM
            DISPLAY SPACE
        END-IF
    END-IF.

PROCESS-GRAPHEME.
    MOVE 0 TO HAS-PREV EPIC-STATE INCB-STATE RI-RUN
    MOVE 0 TO BOUND-COUNT
    MOVE SPACES TO BOUND-TEXT
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > CP-COUNT
        MOVE CP(IDX) TO LOOKUP-CP
        PERFORM LOOKUP-GCB
        PERFORM LOOKUP-INCB
        PERFORM LOOKUP-EXTPICT
        MOVE GCB-CLASS TO BC-CLASS
        MOVE INCB-CLASS TO CUR-INCB
        PERFORM SHOULD-BREAK-BEFORE
        IF BREAK-FLAG = 1
            COMPUTE OFFSET-VAL = IDX - 1
            PERFORM EMIT-BOUNDARY
        END-IF
        PERFORM ADVANCE-STATE
    END-PERFORM
    MOVE CP-COUNT TO OFFSET-VAL
    PERFORM EMIT-BOUNDARY
    COMPUTE CLUSTER-COUNT = BOUND-COUNT - 1.

SHOULD-BREAK-BEFORE.
    IF HAS-PREV = 0
        MOVE 1 TO BREAK-FLAG
    ELSE
        EVALUATE TRUE
        WHEN PC-CLASS = 2 AND BC-CLASS = 3
            MOVE 0 TO BREAK-FLAG
        WHEN PC-CLASS = 4 OR PC-CLASS = 2 OR PC-CLASS = 3
            MOVE 1 TO BREAK-FLAG
        WHEN BC-CLASS = 4 OR BC-CLASS = 2 OR BC-CLASS = 3
            MOVE 1 TO BREAK-FLAG
        WHEN PC-CLASS = 8 AND (BC-CLASS = 8 OR BC-CLASS = 9 OR BC-CLASS = 11 OR BC-CLASS = 12)
            MOVE 0 TO BREAK-FLAG
        WHEN (PC-CLASS = 11 OR PC-CLASS = 9) AND (BC-CLASS = 9 OR BC-CLASS = 10)
            MOVE 0 TO BREAK-FLAG
        WHEN (PC-CLASS = 12 OR PC-CLASS = 10) AND BC-CLASS = 10
            MOVE 0 TO BREAK-FLAG
        WHEN BC-CLASS = 5 OR BC-CLASS = 13
            MOVE 0 TO BREAK-FLAG
        WHEN BC-CLASS = 7
            MOVE 0 TO BREAK-FLAG
        WHEN PC-CLASS = 1
            MOVE 0 TO BREAK-FLAG
        WHEN INCB-STATE = 2 AND CUR-INCB = 2
            MOVE 0 TO BREAK-FLAG
        WHEN EPIC-STATE = 2 AND IS-EP-FLAG = 1
            MOVE 0 TO BREAK-FLAG
        WHEN BC-CLASS = 6 AND FUNCTION MOD(RI-RUN, 2) = 1
            MOVE 0 TO BREAK-FLAG
        WHEN OTHER
            MOVE 1 TO BREAK-FLAG
        END-EVALUATE
    END-IF.

ADVANCE-STATE.
    IF IS-EP-FLAG = 1
        MOVE 1 TO NEW-EPIC
    ELSE
        IF EPIC-STATE = 1 AND BC-CLASS = 5
            MOVE 1 TO NEW-EPIC
        ELSE
            IF EPIC-STATE = 1 AND BC-CLASS = 13
                MOVE 2 TO NEW-EPIC
            ELSE
                MOVE 0 TO NEW-EPIC
            END-IF
        END-IF
    END-IF
    IF CUR-INCB = 2
        MOVE 1 TO NEW-INCB
    ELSE
        IF INCB-STATE = 1 AND CUR-INCB = 1
            MOVE 2 TO NEW-INCB
        ELSE
            IF INCB-STATE = 1 AND CUR-INCB = 3
                MOVE 1 TO NEW-INCB
            ELSE
                IF INCB-STATE = 2 AND CUR-INCB = 1
                    MOVE 2 TO NEW-INCB
                ELSE
                    IF INCB-STATE = 2 AND CUR-INCB = 3
                        MOVE 2 TO NEW-INCB
                    ELSE
                        MOVE 0 TO NEW-INCB
                    END-IF
                END-IF
            END-IF
        END-IF
    END-IF
    IF BC-CLASS = 6
        ADD 1 TO RI-RUN
    ELSE
        MOVE 0 TO RI-RUN
    END-IF
    MOVE NEW-EPIC TO EPIC-STATE
    MOVE NEW-INCB TO INCB-STATE
    MOVE BC-CLASS TO PC-CLASS
    MOVE 1 TO HAS-PREV.

EMIT-BOUNDARY.
    MOVE OFFSET-VAL TO POS-NUM
    IF BOUND-COUNT = 0
        STRING FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE INTO BOUND-TEXT
    ELSE
        STRING FUNCTION TRIM(BOUND-TEXT) DELIMITED BY SIZE
               "," DELIMITED BY SIZE
               FUNCTION TRIM(POS-NUM) DELIMITED BY SIZE
               INTO BOUND-TEXT
    END-IF
    ADD 1 TO BOUND-COUNT.

EMIT-GRAPHEME.
    DISPLAY "BOUNDARIES " FUNCTION TRIM(BOUND-TEXT)
    MOVE CLUSTER-COUNT TO COUNT-TEXT
    DISPLAY "CLUSTERS " FUNCTION TRIM(COUNT-TEXT).

EMIT-RESULT.
    DISPLAY "ACTION " FUNCTION TRIM(ACTION-NAME)
    DISPLAY "INPUT " WITH NO ADVANCING
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > OUT-COUNT
        MOVE OUT-CP(IDX) TO POS-NUM
        IF IDX > 1
            DISPLAY "," WITH NO ADVANCING
        END-IF
        DISPLAY FUNCTION TRIM(POS-NUM) WITH NO ADVANCING
    END-PERFORM
    DISPLAY SPACE
    PERFORM VARYING IDX FROM 1 BY 1 UNTIL IDX > FINDING-COUNT
        DISPLAY "FINDING " FUNCTION TRIM(FINDING-CODE(IDX)) " " FUNCTION TRIM(FINDING-POS(IDX))
    END-PERFORM.
