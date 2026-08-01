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

PROCEDURE DIVISION.
MAIN.
    ACCEPT CMD-LINE FROM COMMAND-LINE
    UNSTRING CMD-LINE DELIMITED BY ALL SPACE
        INTO OP-NAME PROFILE-NAME MODE-NAME NUM-LIST
    END-UNSTRING
    PERFORM PARSE-NUMBERS
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
                        PERFORM SCAN-CORE
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
