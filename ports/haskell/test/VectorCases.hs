{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                           // test // unicode // segmentation // vector-cases
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | The shared segmentation vector fixtures, as data.
--
-- One case per UAX rule, the same bytes every port replays, so each
-- port's segmentation specs ask the same questions instead of a
-- per-port selection of them. The published corpora are the
-- authority; these name which rule each boundary exercises.
--
-- Transcribed from @fixtures/segmentation/line_break_vectors.json@
-- and @fixtures/segmentation/grapheme_vectors.json@. This port
-- declares no JSON dependency and already compiles its published
-- corpora in, so the vectors arrive the same way. Each digest below
-- is of the fixture its cases came from, and the fixture gate
-- recomputes it.
--
-- GENERATED FILE — DO NOT EDIT. Regenerate with
-- @scripts/internal/generate_segmentation_fixtures.py@.

module VectorCases
    ( VectorCase (..)
    , lineBreakAlgorithm
    , lineBreakFixtureDigest
    , lineBreakPublishedRowCount
    , lineBreakCases
    , graphemeAlgorithm
    , graphemeFixtureDigest
    , graphemePublishedRowCount
    , graphemeCases
    ) where

-- | One published case: the rule it pins, what the boundary does, the
-- codepoints, each codepoint's canonical UCD class, and the expected
-- boundary mask.
--
-- The mask is the contract every port reproduces. The classes are
-- recorded for reading: this port names a class @Al@ where the UCD
-- writes @AL@, so comparing them would test a spelling rather than a
-- property.
data VectorCase = VectorCase
    { caseRule :: String
    , caseName :: String
    , caseInput :: [Int]
    , caseClasses :: [String]
    , caseBreaks :: [Bool]
    }

-- | The algorithm these cases judge.
lineBreakAlgorithm :: String
lineBreakAlgorithm = "uax14-line-break"

-- | SHA-256 of the fixture these cases were transcribed from.
lineBreakFixtureDigest :: String
lineBreakFixtureDigest =
    "2a4c0d3ceb3307a8a38a0d579ff2b5021b25fab6e3d8b46805fab45ab5b5c45b"

-- | How many rows the algorithm's published corpus carries, so the
-- corpus gate and the vector gate cannot drift apart.
lineBreakPublishedRowCount :: Int
lineBreakPublishedRowCount = 19338

-- | One case per rule, the same bytes every port replays.
lineBreakCases :: [VectorCase]
lineBreakCases =
    [ VectorCase
        { caseRule = "LB2/LB3"
        , caseName = "start of text never breaks and end of text always does"
        , caseInput = [0x0061, 0x0062]
        , caseClasses = ["AL", "AL"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB4"
        , caseName = "a mandatory break character breaks after itself"
        , caseInput = [0x0061, 0x000C, 0x0062]
        , caseClasses = ["AL", "BK", "AL"]
        , caseBreaks = [False, False, True, True]
        }
    , VectorCase
        { caseRule = "LB5"
        , caseName = "carriage return line feed is not split"
        , caseInput = [0x000D, 0x000A, 0x0061]
        , caseClasses = ["CR", "LF", "AL"]
        , caseBreaks = [False, False, True, True]
        }
    , VectorCase
        { caseRule = "LB6"
        , caseName = "no break falls before a mandatory break character"
        , caseInput = [0x0061, 0x000A]
        , caseClasses = ["AL", "LF"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB7"
        , caseName = "no break falls before a space"
        , caseInput = [0x0061, 0x0020]
        , caseClasses = ["AL", "SP"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB8"
        , caseName = "a zero width space breaks after itself"
        , caseInput = [0x0061, 0x200B, 0x0062]
        , caseClasses = ["AL", "ZW", "AL"]
        , caseBreaks = [False, False, True, True]
        }
    , VectorCase
        { caseRule = "LB8a"
        , caseName = "a zero width joiner glues what follows it"
        , caseInput = [0x0061, 0x200D, 0x0062]
        , caseClasses = ["AL", "ZWJ", "AL"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB9"
        , caseName = "a combining mark takes the class of its base"
        , caseInput = [0x0061, 0x0301]
        , caseClasses = ["AL", "CM"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB10"
        , caseName = "a combining mark with no base stands alone"
        , caseInput = [0x0301, 0x0061]
        , caseClasses = ["CM", "AL"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB11"
        , caseName = "a word joiner glues both sides"
        , caseInput = [0x0061, 0x2060, 0x0062]
        , caseClasses = ["AL", "WJ", "AL"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB12"
        , caseName = "a non-breaking space glues what follows it"
        , caseInput = [0x0061, 0x00A0, 0x0062]
        , caseClasses = ["AL", "GL", "AL"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB13"
        , caseName = "no break falls before a closing parenthesis"
        , caseInput = [0x0061, 0x0029, 0x0062]
        , caseClasses = ["AL", "CP", "AL"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB14"
        , caseName = "no break falls after an opening parenthesis"
        , caseInput = [0x0028, 0x0020, 0x0061]
        , caseClasses = ["OP", "SP", "AL"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB15a"
        , caseName = "an opening quote outside a word glues what follows"
        , caseInput = [0x0020, 0x2018, 0x0061]
        , caseClasses = ["SP", "QU", "AL"]
        , caseBreaks = [False, True, False, True]
        }
    , VectorCase
        { caseRule = "LB15b"
        , caseName = "a closing quote before a space glues what precedes"
        , caseInput = [0x0061, 0x2019, 0x0020, 0x0062]
        , caseClasses = ["AL", "QU", "SP", "AL"]
        , caseBreaks = [False, False, False, True, True]
        }
    , VectorCase
        { caseRule = "LB15c"
        , caseName = "a space before a number opening period breaks"
        , caseInput = [0x0061, 0x0020, 0x002E, 0x0033, 0x0035]
        , caseClasses = ["AL", "SP", "IS", "NU", "NU"]
        , caseBreaks = [False, False, True, False, False, True]
        }
    , VectorCase
        { caseRule = "LB16"
        , caseName = "a closing parenthesis and a following small kana hold together"
        , caseInput = [0x0029, 0x3041]
        , caseClasses = ["CP", "NS"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB17"
        , caseName = "an em dash pair holds together across a space"
        , caseInput = [0x2014, 0x0020, 0x2014]
        , caseClasses = ["B2", "SP", "B2"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB19"
        , caseName = "a quotation mark glues both of its sides"
        , caseInput = [0x0061, 0x0022, 0x0062]
        , caseClasses = ["AL", "QU", "AL"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB20"
        , caseName = "a contingent break opportunity breaks on both sides"
        , caseInput = [0x0061, 0xFFFC, 0x0062]
        , caseClasses = ["AL", "CB", "AL"]
        , caseBreaks = [False, True, True, True]
        }
    , VectorCase
        { caseRule = "LB21"
        , caseName = "a break-after character glues what precedes it"
        , caseInput = [0x0061, 0x00AD, 0x0062]
        , caseClasses = ["AL", "BA", "AL"]
        , caseBreaks = [False, False, True, True]
        }
    , VectorCase
        { caseRule = "LB21a"
        , caseName = "a Hebrew letter and a hyphen glue what follows"
        , caseInput = [0x05D0, 0x002D, 0x0061]
        , caseClasses = ["HL", "HY", "AL"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB21b"
        , caseName = "a solidus and a following Hebrew letter hold together"
        , caseInput = [0x002F, 0x05D0]
        , caseClasses = ["SY", "HL"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB22"
        , caseName = "no break falls before an inseparable"
        , caseInput = [0x0061, 0x2026, 0x0062]
        , caseClasses = ["AL", "IN", "AL"]
        , caseBreaks = [False, False, True, True]
        }
    , VectorCase
        { caseRule = "LB23"
        , caseName = "a letter and a digit hold together"
        , caseInput = [0x0061, 0x0031]
        , caseClasses = ["AL", "NU"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB23a"
        , caseName = "a currency symbol and an ideograph hold together"
        , caseInput = [0x0024, 0x4E00]
        , caseClasses = ["PR", "ID"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB24"
        , caseName = "a prefix and a letter hold together"
        , caseInput = [0x0024, 0x0061]
        , caseClasses = ["PR", "AL"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB25"
        , caseName = "a numeric chain holds together across its separator"
        , caseInput = [0x0031, 0x002C, 0x0030, 0x0030, 0x0030]
        , caseClasses = ["NU", "IS", "NU", "NU", "NU"]
        , caseBreaks = [False, False, False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB26"
        , caseName = "Hangul jamo hold together"
        , caseInput = [0x1100, 0x1161, 0x11A8]
        , caseClasses = ["JL", "JV", "JT"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB27"
        , caseName = "a Hangul syllable and a following inseparable hold together"
        , caseInput = [0xAC00, 0x2026]
        , caseClasses = ["H2", "IN"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB28"
        , caseName = "two letters hold together"
        , caseInput = [0x0061, 0x0062]
        , caseClasses = ["AL", "AL"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB28a.1"
        , caseName = "an aksara pre-base glues the cluster base after it"
        , caseInput = [0x11003, 0x1B05]
        , caseClasses = ["AP", "AK"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB28a.2"
        , caseName = "a cluster base glues a following vowel form"
        , caseInput = [0x1B05, 0x1BF2]
        , caseClasses = ["AK", "VF"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB28a.3"
        , caseName = "a virama between cluster bases glues both"
        , caseInput = [0x1B05, 0x1B44, 0x1B05]
        , caseClasses = ["AK", "VI", "AK"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB28a.4"
        , caseName = "two cluster bases glue when a vowel form follows"
        , caseInput = [0x1B05, 0x1B05, 0x1BF2]
        , caseClasses = ["AK", "AK", "VF"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB29"
        , caseName = "a full stop and a following letter hold together"
        , caseInput = [0x002E, 0x0061]
        , caseClasses = ["IS", "AL"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB30"
        , caseName = "a letter and an opening parenthesis hold together"
        , caseInput = [0x0061, 0x0028, 0x0031]
        , caseClasses = ["AL", "OP", "NU"]
        , caseBreaks = [False, False, False, True]
        }
    , VectorCase
        { caseRule = "LB30a"
        , caseName = "regional indicators pair off"
        , caseInput = [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8]
        , caseClasses = ["RI", "RI", "RI", "RI"]
        , caseBreaks = [False, False, True, False, True]
        }
    , VectorCase
        { caseRule = "LB30b"
        , caseName = "an emoji modifier stays on its base"
        , caseInput = [0x1F466, 0x1F3FB]
        , caseClasses = ["EB", "EM"]
        , caseBreaks = [False, False, True]
        }
    , VectorCase
        { caseRule = "LB31"
        , caseName = "a space opens the next line"
        , caseInput = [0x0061, 0x0020, 0x0062]
        , caseClasses = ["AL", "SP", "AL"]
        , caseBreaks = [False, False, True, True]
        }
    , VectorCase
        { caseRule = "LB1"
        , caseName = "an empty sequence carries one boundary"
        , caseInput = []
        , caseClasses = []
        , caseBreaks = [True]
        }
    ]

-- | The algorithm these cases judge.
graphemeAlgorithm :: String
graphemeAlgorithm = "uax29-grapheme-cluster"

-- | SHA-256 of the fixture these cases were transcribed from.
graphemeFixtureDigest :: String
graphemeFixtureDigest =
    "7bb180dfce2604ffccd6006d7a32330d9021128f79cac228b053d60bf2f28f59"

-- | How many rows the algorithm's published corpus carries, so the
-- corpus gate and the vector gate cannot drift apart.
graphemePublishedRowCount :: Int
graphemePublishedRowCount = 766

-- | One case per rule, the same bytes every port replays.
graphemeCases :: [VectorCase]
graphemeCases =
    [ VectorCase
        { caseRule = "GB1/GB2"
        , caseName = "start and end of text are both boundaries"
        , caseInput = [0x0061]
        , caseClasses = ["Other"]
        , caseBreaks = [True, True]
        }
    , VectorCase
        { caseRule = "GB3"
        , caseName = "carriage return line feed is one cluster"
        , caseInput = [0x000D, 0x000A]
        , caseClasses = ["CR", "LF"]
        , caseBreaks = [True, False, True]
        }
    , VectorCase
        { caseRule = "GB4"
        , caseName = "a control character ends its cluster"
        , caseInput = [0x000D, 0x0061]
        , caseClasses = ["CR", "Other"]
        , caseBreaks = [True, True, True]
        }
    , VectorCase
        { caseRule = "GB5"
        , caseName = "a control character starts its own cluster"
        , caseInput = [0x0061, 0x000D]
        , caseClasses = ["Other", "CR"]
        , caseBreaks = [True, True, True]
        }
    , VectorCase
        { caseRule = "GB6"
        , caseName = "a leading jamo and a vowel jamo hold together"
        , caseInput = [0x1100, 0x1161]
        , caseClasses = ["L", "V"]
        , caseBreaks = [True, False, True]
        }
    , VectorCase
        { caseRule = "GB7"
        , caseName = "a vowel jamo and a trailing jamo hold together"
        , caseInput = [0x1161, 0x11A8]
        , caseClasses = ["V", "T"]
        , caseBreaks = [True, False, True]
        }
    , VectorCase
        { caseRule = "GB8"
        , caseName = "a syllable and a trailing jamo hold together"
        , caseInput = [0xAC01, 0x11A8]
        , caseClasses = ["LVT", "T"]
        , caseBreaks = [True, False, True]
        }
    , VectorCase
        { caseRule = "GB9"
        , caseName = "a combining mark joins its base"
        , caseInput = [0x0065, 0x0301]
        , caseClasses = ["Other", "Extend"]
        , caseBreaks = [True, False, True]
        }
    , VectorCase
        { caseRule = "GB9a"
        , caseName = "a spacing mark joins its base"
        , caseInput = [0x0915, 0x093E]
        , caseClasses = ["Other", "SpacingMark"]
        , caseBreaks = [True, False, True]
        }
    , VectorCase
        { caseRule = "GB9b"
        , caseName = "a prepended concatenation mark joins what follows"
        , caseInput = [0x0600, 0x0661]
        , caseClasses = ["Prepend", "Other"]
        , caseBreaks = [True, False, True]
        }
    , VectorCase
        { caseRule = "GB9c"
        , caseName = "an Indic conjunct holds together across its linker"
        , caseInput = [0x0915, 0x094D, 0x0916]
        , caseClasses = ["Other", "Extend", "Other"]
        , caseBreaks = [True, False, False, True]
        }
    , VectorCase
        { caseRule = "GB11"
        , caseName = "an emoji zero-width-joiner sequence is one cluster"
        , caseInput = [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467]
        , caseClasses = ["Other", "ZWJ", "Other", "ZWJ", "Other"]
        , caseBreaks = [True, False, False, False, False, True]
        }
    , VectorCase
        { caseRule = "GB12/GB13"
        , caseName = "regional indicators pair off"
        , caseInput = [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8]
        , caseClasses = ["Regional_Indicator", "Regional_Indicator", "Regional_Indicator", "Regional_Indicator"]
        , caseBreaks = [True, False, True, False, True]
        }
    , VectorCase
        { caseRule = "GB999"
        , caseName = "two letters are two clusters"
        , caseInput = [0x0061, 0x0062]
        , caseClasses = ["Other", "Other"]
        , caseBreaks = [True, True, True]
        }
    , VectorCase
        { caseRule = "GB1"
        , caseName = "an empty sequence carries one boundary"
        , caseInput = []
        , caseClasses = []
        , caseBreaks = [True]
        }
    ]
