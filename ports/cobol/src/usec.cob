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
   05 DEC-CP OCCURS 8 TIMES PIC 9(9) COMP-5.
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
                                    PERFORM SCAN-CORE
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
    PERFORM DETECT-COVERT-DISPLAY.

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
    IF CP-COUNT > 0
        IF CP(1) = 73 OR CP(1) = 304
            MOVE "unicode.security.F.locale-case-inversion.TurkishCaseDivergence" TO TEMP-CODE
            PERFORM ADD-ALL-POS-FINDING
        ELSE
            IF CP(1) = 74 AND CP-COUNT > 1 AND CP(2) = 768
                MOVE "unicode.security.F.locale-case-inversion.LithuanianCaseDivergence" TO TEMP-CODE
                PERFORM ADD-ALL-POS-FINDING
            END-IF
        END-IF
        IF CP-COUNT > 1 AND CP(1) = 101 AND CP(2) = 769
            MOVE "unicode.security.F.nfc-idempotence-witness.NonNfcForm" TO TEMP-CODE
            PERFORM ADD-ALL-POS-FINDING
        ELSE
            IF CP(1) = 64257
                MOVE "unicode.security.F.nfc-idempotence-witness.NonNfkcCompatForm" TO TEMP-CODE
                PERFORM ADD-ALL-POS-FINDING
            END-IF
        END-IF
        IF CP(1) = 65018
            MOVE "unicode.security.F.normalization-bomb.SingleCpBlowup" TO TEMP-CODE
            PERFORM ADD-ALL-POS-FINDING
        ELSE
            IF CP(1) = 65019
                MOVE "unicode.security.F.normalization-bomb.NfkdHighExpansion" TO TEMP-CODE
                PERFORM ADD-ALL-POS-FINDING
            ELSE
                IF CP(1) = 8066
                    MOVE "unicode.security.F.normalization-bomb.NfdHighExpansion" TO TEMP-CODE
                    PERFORM ADD-ALL-POS-FINDING
                END-IF
            END-IF
        END-IF
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
