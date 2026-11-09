package com.unicodesecurity;

// The shared segmentation vector fixtures, as data.
//
// One case per UAX rule, the same bytes every port replays, so each
// port's segmentation tests ask the same questions instead of a
// per-port selection of them. The published corpora are the
// authority; these name which rule each boundary exercises.
//
// Transcribed from fixtures/segmentation/line_break_vectors.json and
// fixtures/segmentation/grapheme_vectors.json. The package declares
// no JSON dependency and the self-contained gate refuses a host file
// read under its main sources, so the vectors are code. Each digest
// below is of the fixture its cases came from, and the fixture gate
// recomputes it.
//
// GENERATED FILE - DO NOT EDIT. Regenerate with
// scripts/internal/generate_segmentation_fixtures.py.
final class VectorCases {
  private VectorCases() {}

  // One published case: the rule it pins, what the boundary does, the
  // code points, each code point's canonical UCD class, and the
  // expected boundary mask.
  //
  // The mask is the contract every port reproduces. The classes are
  // recorded for reading: this port names a class by an int code and
  // the UCD writes AL, so comparing them would test a spelling
  // rather than a property.
  record VectorCase(
      String rule, String name, int[] input, String[] classes,
      boolean[] breaks) {}

  // The algorithm these cases judge.
  static final String LINE_BREAK_ALGORITHM = "uax14-line-break";

  // SHA-256 of the fixture these cases were transcribed from.
  static final String LINE_BREAK_FIXTURE_DIGEST =
      "2a4c0d3ceb3307a8a38a0d579ff2b5021b25fab6e3d8b46805fab45ab5b5c45b";

  // How many rows the algorithm's published corpus carries, so the
  // corpus gate and the vector gate cannot drift apart.
  static final int LINE_BREAK_PUBLISHED_ROW_COUNT = 19338;

  // One case per rule, the same bytes every port replays.
  static final VectorCase[] LINE_BREAK_CASES = {
    new VectorCase(
        "LB2/LB3",
        "start of text never breaks and end of text always does",
        new int[] {0x0061, 0x0062},
        new String[] {"AL", "AL"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB4",
        "a mandatory break character breaks after itself",
        new int[] {0x0061, 0x000C, 0x0062},
        new String[] {"AL", "BK", "AL"},
        new boolean[] {false, false, true, true}),
    new VectorCase(
        "LB5",
        "carriage return line feed is not split",
        new int[] {0x000D, 0x000A, 0x0061},
        new String[] {"CR", "LF", "AL"},
        new boolean[] {false, false, true, true}),
    new VectorCase(
        "LB6",
        "no break falls before a mandatory break character",
        new int[] {0x0061, 0x000A},
        new String[] {"AL", "LF"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB7",
        "no break falls before a space",
        new int[] {0x0061, 0x0020},
        new String[] {"AL", "SP"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB8",
        "a zero width space breaks after itself",
        new int[] {0x0061, 0x200B, 0x0062},
        new String[] {"AL", "ZW", "AL"},
        new boolean[] {false, false, true, true}),
    new VectorCase(
        "LB8a",
        "a zero width joiner glues what follows it",
        new int[] {0x0061, 0x200D, 0x0062},
        new String[] {"AL", "ZWJ", "AL"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB9",
        "a combining mark takes the class of its base",
        new int[] {0x0061, 0x0301},
        new String[] {"AL", "CM"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB10",
        "a combining mark with no base stands alone",
        new int[] {0x0301, 0x0061},
        new String[] {"CM", "AL"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB11",
        "a word joiner glues both sides",
        new int[] {0x0061, 0x2060, 0x0062},
        new String[] {"AL", "WJ", "AL"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB12",
        "a non-breaking space glues what follows it",
        new int[] {0x0061, 0x00A0, 0x0062},
        new String[] {"AL", "GL", "AL"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB13",
        "no break falls before a closing parenthesis",
        new int[] {0x0061, 0x0029, 0x0062},
        new String[] {"AL", "CP", "AL"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB14",
        "no break falls after an opening parenthesis",
        new int[] {0x0028, 0x0020, 0x0061},
        new String[] {"OP", "SP", "AL"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB15a",
        "an opening quote outside a word glues what follows",
        new int[] {0x0020, 0x2018, 0x0061},
        new String[] {"SP", "QU", "AL"},
        new boolean[] {false, true, false, true}),
    new VectorCase(
        "LB15b",
        "a closing quote before a space glues what precedes",
        new int[] {0x0061, 0x2019, 0x0020, 0x0062},
        new String[] {"AL", "QU", "SP", "AL"},
        new boolean[] {false, false, false, true, true}),
    new VectorCase(
        "LB15c",
        "a space before a number opening period breaks",
        new int[] {0x0061, 0x0020, 0x002E, 0x0033, 0x0035},
        new String[] {"AL", "SP", "IS", "NU", "NU"},
        new boolean[] {false, false, true, false, false, true}),
    new VectorCase(
        "LB16",
        "a closing parenthesis and a following small kana hold together",
        new int[] {0x0029, 0x3041},
        new String[] {"CP", "NS"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB17",
        "an em dash pair holds together across a space",
        new int[] {0x2014, 0x0020, 0x2014},
        new String[] {"B2", "SP", "B2"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB19",
        "a quotation mark glues both of its sides",
        new int[] {0x0061, 0x0022, 0x0062},
        new String[] {"AL", "QU", "AL"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB20",
        "a contingent break opportunity breaks on both sides",
        new int[] {0x0061, 0xFFFC, 0x0062},
        new String[] {"AL", "CB", "AL"},
        new boolean[] {false, true, true, true}),
    new VectorCase(
        "LB21",
        "a break-after character glues what precedes it",
        new int[] {0x0061, 0x00AD, 0x0062},
        new String[] {"AL", "BA", "AL"},
        new boolean[] {false, false, true, true}),
    new VectorCase(
        "LB21a",
        "a Hebrew letter and a hyphen glue what follows",
        new int[] {0x05D0, 0x002D, 0x0061},
        new String[] {"HL", "HY", "AL"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB21b",
        "a solidus and a following Hebrew letter hold together",
        new int[] {0x002F, 0x05D0},
        new String[] {"SY", "HL"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB22",
        "no break falls before an inseparable",
        new int[] {0x0061, 0x2026, 0x0062},
        new String[] {"AL", "IN", "AL"},
        new boolean[] {false, false, true, true}),
    new VectorCase(
        "LB23",
        "a letter and a digit hold together",
        new int[] {0x0061, 0x0031},
        new String[] {"AL", "NU"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB23a",
        "a currency symbol and an ideograph hold together",
        new int[] {0x0024, 0x4E00},
        new String[] {"PR", "ID"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB24",
        "a prefix and a letter hold together",
        new int[] {0x0024, 0x0061},
        new String[] {"PR", "AL"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB25",
        "a numeric chain holds together across its separator",
        new int[] {0x0031, 0x002C, 0x0030, 0x0030, 0x0030},
        new String[] {"NU", "IS", "NU", "NU", "NU"},
        new boolean[] {false, false, false, false, false, true}),
    new VectorCase(
        "LB26",
        "Hangul jamo hold together",
        new int[] {0x1100, 0x1161, 0x11A8},
        new String[] {"JL", "JV", "JT"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB27",
        "a Hangul syllable and a following inseparable hold together",
        new int[] {0xAC00, 0x2026},
        new String[] {"H2", "IN"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB28",
        "two letters hold together",
        new int[] {0x0061, 0x0062},
        new String[] {"AL", "AL"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB28a.1",
        "an aksara pre-base glues the cluster base after it",
        new int[] {0x11003, 0x1B05},
        new String[] {"AP", "AK"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB28a.2",
        "a cluster base glues a following vowel form",
        new int[] {0x1B05, 0x1BF2},
        new String[] {"AK", "VF"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB28a.3",
        "a virama between cluster bases glues both",
        new int[] {0x1B05, 0x1B44, 0x1B05},
        new String[] {"AK", "VI", "AK"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB28a.4",
        "two cluster bases glue when a vowel form follows",
        new int[] {0x1B05, 0x1B05, 0x1BF2},
        new String[] {"AK", "AK", "VF"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB29",
        "a full stop and a following letter hold together",
        new int[] {0x002E, 0x0061},
        new String[] {"IS", "AL"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB30",
        "a letter and an opening parenthesis hold together",
        new int[] {0x0061, 0x0028, 0x0031},
        new String[] {"AL", "OP", "NU"},
        new boolean[] {false, false, false, true}),
    new VectorCase(
        "LB30a",
        "regional indicators pair off",
        new int[] {0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8},
        new String[] {"RI", "RI", "RI", "RI"},
        new boolean[] {false, false, true, false, true}),
    new VectorCase(
        "LB30b",
        "an emoji modifier stays on its base",
        new int[] {0x1F466, 0x1F3FB},
        new String[] {"EB", "EM"},
        new boolean[] {false, false, true}),
    new VectorCase(
        "LB31",
        "a space opens the next line",
        new int[] {0x0061, 0x0020, 0x0062},
        new String[] {"AL", "SP", "AL"},
        new boolean[] {false, false, true, true}),
    new VectorCase(
        "LB1",
        "an empty sequence carries one boundary",
        new int[] {},
        new String[] {},
        new boolean[] {true}),
  };

  // The algorithm these cases judge.
  static final String GRAPHEME_ALGORITHM = "uax29-grapheme-cluster";

  // SHA-256 of the fixture these cases were transcribed from.
  static final String GRAPHEME_FIXTURE_DIGEST =
      "7bb180dfce2604ffccd6006d7a32330d9021128f79cac228b053d60bf2f28f59";

  // How many rows the algorithm's published corpus carries, so the
  // corpus gate and the vector gate cannot drift apart.
  static final int GRAPHEME_PUBLISHED_ROW_COUNT = 766;

  // One case per rule, the same bytes every port replays.
  static final VectorCase[] GRAPHEME_CASES = {
    new VectorCase(
        "GB1/GB2",
        "start and end of text are both boundaries",
        new int[] {0x0061},
        new String[] {"Other"},
        new boolean[] {true, true}),
    new VectorCase(
        "GB3",
        "carriage return line feed is one cluster",
        new int[] {0x000D, 0x000A},
        new String[] {"CR", "LF"},
        new boolean[] {true, false, true}),
    new VectorCase(
        "GB4",
        "a control character ends its cluster",
        new int[] {0x000D, 0x0061},
        new String[] {"CR", "Other"},
        new boolean[] {true, true, true}),
    new VectorCase(
        "GB5",
        "a control character starts its own cluster",
        new int[] {0x0061, 0x000D},
        new String[] {"Other", "CR"},
        new boolean[] {true, true, true}),
    new VectorCase(
        "GB6",
        "a leading jamo and a vowel jamo hold together",
        new int[] {0x1100, 0x1161},
        new String[] {"L", "V"},
        new boolean[] {true, false, true}),
    new VectorCase(
        "GB7",
        "a vowel jamo and a trailing jamo hold together",
        new int[] {0x1161, 0x11A8},
        new String[] {"V", "T"},
        new boolean[] {true, false, true}),
    new VectorCase(
        "GB8",
        "a syllable and a trailing jamo hold together",
        new int[] {0xAC01, 0x11A8},
        new String[] {"LVT", "T"},
        new boolean[] {true, false, true}),
    new VectorCase(
        "GB9",
        "a combining mark joins its base",
        new int[] {0x0065, 0x0301},
        new String[] {"Other", "Extend"},
        new boolean[] {true, false, true}),
    new VectorCase(
        "GB9a",
        "a spacing mark joins its base",
        new int[] {0x0915, 0x093E},
        new String[] {"Other", "SpacingMark"},
        new boolean[] {true, false, true}),
    new VectorCase(
        "GB9b",
        "a prepended concatenation mark joins what follows",
        new int[] {0x0600, 0x0661},
        new String[] {"Prepend", "Other"},
        new boolean[] {true, false, true}),
    new VectorCase(
        "GB9c",
        "an Indic conjunct holds together across its linker",
        new int[] {0x0915, 0x094D, 0x0916},
        new String[] {"Other", "Extend", "Other"},
        new boolean[] {true, false, false, true}),
    new VectorCase(
        "GB11",
        "an emoji zero-width-joiner sequence is one cluster",
        new int[] {0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467},
        new String[] {"Other", "ZWJ", "Other", "ZWJ", "Other"},
        new boolean[] {true, false, false, false, false, true}),
    new VectorCase(
        "GB12/GB13",
        "regional indicators pair off",
        new int[] {0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8},
        new String[] {"Regional_Indicator", "Regional_Indicator", "Regional_Indicator", "Regional_Indicator"},
        new boolean[] {true, false, true, false, true}),
    new VectorCase(
        "GB999",
        "two letters are two clusters",
        new int[] {0x0061, 0x0062},
        new String[] {"Other", "Other"},
        new boolean[] {true, true, true}),
    new VectorCase(
        "GB1",
        "an empty sequence carries one boundary",
        new int[] {},
        new String[] {},
        new boolean[] {true}),
  };
}
