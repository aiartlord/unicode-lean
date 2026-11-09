package com.unicodesecurity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// UAX #29 default extended grapheme cluster segmentation.
//
// Validates the port's cluster breaker against the official Unicode
// GraphemeBreakTest.txt (bundled under testdata/ so the port stays
// self-contained), plus the shared vector fixture every other port replays and
// targeted cases for shapes a boundary mask does not state.
//
// Those two corpus gates are the spec repo's own: agree with every published
// row, and separately account for the whole file so a row lost between the file
// and the fold fails rather than shrinking the denominator.
public final class GraphemeContractTest {
  // The markers the published break corpus writes at each boundary.
  private static final String BREAK = "÷";
  private static final String NO_BREAK = "×";

  private static final Path CORPUS = Path.of("testdata", "GraphemeBreakTest.txt");

  public static void main(String[] args) throws Exception {
    List<Row> rows = readCorpus();
    testCorpusIsWellFormed(rows);
    testAgreesWithEveryPublishedRow(rows);
    testSharedVectors();
    testOutputShape();
    testClustersAndClasses();
    System.out.println("clean: JVM grapheme clustering passes ("
        + rows.size() + " published rows, "
        + VectorCases.GRAPHEME_CASES.length + " shared vector cases)");
  }

  // One published case: its line in the file, its code points and the expected
  // boundary mask.
  private record Row(int line, int[] codepoints, boolean[] expected) {}

  private static List<Row> readCorpus() throws IOException {
    List<Row> rows = new ArrayList<>();
    List<String> lines = Files.readAllLines(CORPUS);
    for (int index = 0; index < lines.size(); index++) {
      String raw = lines.get(index);
      int hash = raw.indexOf('#');
      String body = (hash >= 0 ? raw.substring(0, hash) : raw).trim();
      if (body.isEmpty()) {
        continue;
      }
      List<Integer> codepoints = new ArrayList<>();
      List<Boolean> expected = new ArrayList<>();
      for (String token : body.split("\\s+")) {
        if (token.isEmpty()) {
          continue;
        }
        if (token.equals(BREAK)) {
          expected.add(Boolean.TRUE);
        } else if (token.equals(NO_BREAK)) {
          expected.add(Boolean.FALSE);
        } else {
          codepoints.add(Integer.parseInt(token, 16));
        }
      }
      int[] cps = new int[codepoints.size()];
      for (int i = 0; i < cps.length; i++) {
        cps[i] = codepoints.get(i);
      }
      boolean[] flags = new boolean[expected.size()];
      for (int i = 0; i < flags.length; i++) {
        flags[i] = expected.get(i);
      }
      rows.add(new Row(index + 1, cps, flags));
    }
    return rows;
  }

  // What the corpus must be before it can judge anything: every row carries one
  // more flag than code points, and the vendored copy carries every row the
  // canonical file did.
  private static void testCorpusIsWellFormed(List<Row> rows) {
    int ragged = 0;
    for (Row row : rows) {
      if (row.expected().length != row.codepoints().length + 1) {
        ragged++;
      }
    }
    assertEquals(0, ragged, "rows carrying a wrong flag count");
    assertEquals(GraphemeTables.PUBLISHED_ROW_COUNT, rows.size(),
        "the vendored corpus carries every published row");
  }

  // Hand-written vectors cannot establish a segmentation algorithm: its rules
  // read context on both sides of a boundary and the answer depends on state
  // carried from earlier in the sequence, so a wrong rule survives any vector a
  // person would pick.
  private static void testAgreesWithEveryPublishedRow(List<Row> rows) {
    int disagreements = 0;
    String detail = "";
    for (Row row : rows) {
      boolean[] produced = Grapheme.graphemeBreaks(row.codepoints());
      if (!Arrays.equals(produced, row.expected())) {
        if (disagreements == 0) {
          detail = "line " + row.line()
              + "\n  codepoints: " + formatCodepoints(row.codepoints())
              + "\n  published : " + formatFlags(row.expected())
              + "\n  produced  : " + formatFlags(produced);
        }
        disagreements++;
      }
    }
    assertTrue(disagreements == 0,
        disagreements + " of " + rows.size() + " published rows disagree; "
            + "first at " + detail);
  }

  // One case per UAX #29 rule, the same bytes every port replays, so no port can
  // carry a weaker set of rule checks than another. The published corpus above
  // is the authority; these name which rule each boundary exercises.
  private static void testSharedVectors() {
    assertEquals("uax29-grapheme-cluster", VectorCases.GRAPHEME_ALGORITHM,
        "the fixture is the grapheme one");
    assertTrue(VectorCases.GRAPHEME_CASES.length > 0,
        "the fixture carries cases");
    assertEquals(GraphemeTables.PUBLISHED_ROW_COUNT,
        VectorCases.GRAPHEME_PUBLISHED_ROW_COUNT,
        "the corpus and the vectors agree on the row count");
    for (VectorCases.VectorCase entry : VectorCases.GRAPHEME_CASES) {
      boolean[] produced = Grapheme.graphemeBreaks(entry.input());
      assertTrue(Arrays.equals(produced, entry.breaks()),
          entry.rule() + ": " + entry.name()
              + "\n  codepoints: " + formatCodepoints(entry.input())
              + "\n  fixture   : " + formatFlags(entry.breaks())
              + "\n  produced  : " + formatFlags(produced));
    }
  }

  private static void testOutputShape() {
    // One flag per boundary: cps.length + 1, with both ends always a break.
    for (int length = 0; length < 8; length++) {
      int[] cps = new int[length];
      for (int i = 0; i < length; i++) {
        cps[i] = 0x61 + i;
      }
      boolean[] breaks = Grapheme.graphemeBreaks(cps);
      assertEquals(length + 1, breaks.length,
          "one flag per boundary at length " + length);
      assertTrue(breaks[breaks.length - 1], "GB2 breaks at the end of text");
      if (length > 0) {
        assertTrue(breaks[0], "GB1 breaks at the start of text");
      }
    }
  }

  private static void testClustersAndClasses() {
    // The cluster split is a shape the boundary masks do not state. GB999
    // leaves each ASCII letter its own cluster; GB9 keeps a combining mark with
    // its base; GB3 keeps CR LF together; GB12 pairs regional indicators; and
    // GB11 holds an emoji ZWJ sequence together.
    assertEquals(3, Grapheme.graphemeClusters(new int[] {0x61, 0x62, 0x63}).length,
        "ascii letters are their own clusters");
    assertEquals(1, Grapheme.graphemeClusters(new int[] {0x65, 0x0301}).length,
        "a combining mark joins its base");
    assertEquals(1, Grapheme.graphemeClusters(new int[] {0x0D, 0x0A}).length,
        "CR LF is one cluster");
    assertEquals(1, Grapheme.graphemeClusters(new int[] {0x1F1EF, 0x1F1F5}).length,
        "a regional-indicator pair is one cluster");
    assertEquals(2,
        Grapheme.graphemeClusters(new int[] {0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8}).length,
        "four regional indicators are two clusters");
    assertEquals(1,
        Grapheme.graphemeClusters(
            new int[] {0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467}).length,
        "an emoji ZWJ sequence is one cluster");
    int[][] clusters = Grapheme.graphemeClusters(new int[] {0x65, 0x0301, 0x61});
    assertEquals(2, clusters.length, "a base with a mark then a letter is two clusters");
    assertTrue(Arrays.equals(new int[] {0x65, 0x0301}, clusters[0]),
        "the mark stays with its base");
    assertTrue(Arrays.equals(new int[] {0x61}, clusters[1]),
        "the letter after it opens the next cluster");

    // The three properties the rules read, each through its generated table.
    assertEquals(GraphemeTables.GCB_CR, Grapheme.lookupGcb(0x000D), "U+000D is CR");
    assertEquals(GraphemeTables.GCB_LF, Grapheme.lookupGcb(0x000A), "U+000A is LF");
    assertEquals(GraphemeTables.GCB_EXTEND, Grapheme.lookupGcb(0x0301),
        "U+0301 is Extend");
    assertEquals(GraphemeTables.GCB_ZWJ, Grapheme.lookupGcb(0x200D), "U+200D is ZWJ");
    assertEquals(GraphemeTables.GCB_REGIONAL_INDICATOR, Grapheme.lookupGcb(0x1F1EF),
        "U+1F1EF is Regional_Indicator");
    assertEquals(GraphemeTables.GCB_SPACING_MARK, Grapheme.lookupGcb(0x093E),
        "U+093E is SpacingMark");
    // A code point no range covers takes the property's Other default.
    assertEquals(GraphemeTables.GCB_OTHER, Grapheme.lookupGcb(0x0061), "U+0061 is Other");

    // GB9c reads Indic_Conjunct_Break: U+094D DEVANAGARI SIGN VIRAMA is the
    // Linker, U+0915 KA a Consonant.
    assertEquals(GraphemeTables.INCB_LINKER, Grapheme.lookupIncb(0x094D),
        "U+094D is the Indic conjunct Linker");
    assertEquals(GraphemeTables.INCB_CONSONANT, Grapheme.lookupIncb(0x0915),
        "U+0915 is an Indic conjunct Consonant");
    assertEquals(GraphemeTables.INCB_NONE, Grapheme.lookupIncb(0x0061),
        "U+0061 carries no Indic_Conjunct_Break");

    // GB11 reads Extended_Pictographic.
    assertTrue(Grapheme.isExtendedPictographic(0x1F466),
        "U+1F466 is Extended_Pictographic");
    assertTrue(!Grapheme.isExtendedPictographic(0x0061),
        "U+0061 is not Extended_Pictographic");
  }

  private static String formatCodepoints(int[] cps) {
    StringBuilder out = new StringBuilder();
    for (int cp : cps) {
      if (out.length() > 0) {
        out.append(' ');
      }
      out.append(String.format("%04X", cp));
    }
    return out.toString();
  }

  private static String formatFlags(boolean[] flags) {
    StringBuilder out = new StringBuilder();
    for (boolean flag : flags) {
      if (out.length() > 0) {
        out.append(' ');
      }
      out.append(flag ? '/' : 'x');
    }
    return out.toString();
  }

  private static void assertTrue(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }

  private static void assertEquals(Object expected, Object actual,
      String message) {
    if (!java.util.Objects.equals(expected, actual)) {
      throw new AssertionError(
          message + ": expected " + expected + " but was " + actual);
    }
  }
}
