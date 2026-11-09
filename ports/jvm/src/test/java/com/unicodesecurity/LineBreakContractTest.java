package com.unicodesecurity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// UAX #14 default line breaking.
//
// Validates the port's line breaker against the official Unicode
// LineBreakTest.txt (bundled under testdata/ so the port stays
// self-contained), plus the shared vector fixture every other port replays and
// targeted cases for shapes a boundary mask does not state.
//
// Those two corpus gates are the spec repo's own: agree with every published
// row, and separately account for the whole file so a row lost between the file
// and the fold fails rather than shrinking the denominator.
public final class LineBreakContractTest {
  // The markers the published break corpus writes at each boundary.
  private static final String BREAK = "÷";
  private static final String NO_BREAK = "×";

  private static final Path CORPUS = Path.of("testdata", "LineBreakTest.txt");

  public static void main(String[] args) throws Exception {
    List<Row> rows = readCorpus();
    testCorpusIsWellFormed(rows);
    testAgreesWithEveryPublishedRow(rows);
    testSharedVectors();
    testOutputShape();
    testRunsAndClasses();
    System.out.println("clean: JVM line breaking passes ("
        + rows.size() + " published rows, "
        + VectorCases.LINE_BREAK_CASES.length + " shared vector cases)");
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
    assertEquals(LineBreakTables.PUBLISHED_ROW_COUNT, rows.size(),
        "the vendored corpus carries every published row");
  }

  // Hand-written vectors cannot establish a segmentation algorithm: its rules
  // read context on both sides of a boundary and the answer depends on state
  // carried from earlier in the sequence, so a wrong rule survives any vector a
  // person would pick. Agreeing with all of them is also the evidence the two
  // departures declared at LineBreak's head needed.
  private static void testAgreesWithEveryPublishedRow(List<Row> rows) {
    int disagreements = 0;
    String detail = "";
    for (Row row : rows) {
      boolean[] produced = LineBreak.lineBreaks(row.codepoints());
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

  // One case per UAX #14 rule, the same bytes every port replays, so no port can
  // carry a weaker set of rule checks than another. The published corpus above
  // is the authority; these name which rule each boundary exercises.
  private static void testSharedVectors() {
    assertEquals("uax14-line-break", VectorCases.LINE_BREAK_ALGORITHM,
        "the fixture is the line-break one");
    assertTrue(VectorCases.LINE_BREAK_CASES.length > 0,
        "the fixture carries cases");
    assertEquals(LineBreakTables.PUBLISHED_ROW_COUNT,
        VectorCases.LINE_BREAK_PUBLISHED_ROW_COUNT,
        "the corpus and the vectors agree on the row count");
    for (VectorCases.VectorCase entry : VectorCases.LINE_BREAK_CASES) {
      boolean[] produced = LineBreak.lineBreaks(entry.input());
      assertTrue(Arrays.equals(produced, entry.breaks()),
          entry.rule() + ": " + entry.name()
              + "\n  codepoints: " + formatCodepoints(entry.input())
              + "\n  fixture   : " + formatFlags(entry.breaks())
              + "\n  produced  : " + formatFlags(produced));
    }
  }

  private static void testOutputShape() {
    // The Lean lineBreaks_length theorem: cps.length + 1 flags.
    for (int length = 0; length < 8; length++) {
      int[] cps = new int[length];
      for (int i = 0; i < length; i++) {
        cps[i] = 0x61 + i;
      }
      assertEquals(length + 1, LineBreak.lineBreaks(cps).length,
          "one flag per boundary at length " + length);
    }
  }

  private static void testRunsAndClasses() {
    // LB18 breaks after a space, so the space stays with the word before it.
    // The run split is a shape the boundary masks do not state.
    int[][] runs = LineBreak.lineRuns(new int[] {0x61, 0x20, 0x62});
    assertEquals(2, runs.length, "a space opens the next run");
    assertTrue(Arrays.equals(new int[] {0x61, 0x20}, runs[0]),
        "the space stays with the word before it");
    assertTrue(Arrays.equals(new int[] {0x62}, runs[1]),
        "the next run starts after the space");

    // LB25: "1,000" is one run across its separator.
    assertEquals(1,
        LineBreak.lineRuns(new int[] {0x31, 0x2C, 0x30, 0x30, 0x30}).length,
        "a numeric chain is one run");

    // LB1 resolves the tailorable classes into the working alphabet.
    assertEquals("CJ", LineBreak.rawClass(0x3041), "U+3041 is CJ");
    assertEquals("NS", LineBreak.resolvedClass(0x3041), "LB1 reads CJ as NS");
    assertEquals("AI", LineBreak.rawClass(0x00A7), "U+00A7 is AI");
    assertEquals("AL", LineBreak.resolvedClass(0x00A7), "LB1 reads AI as AL");
    assertEquals("SG", LineBreak.rawClass(0xD800), "a surrogate is SG");
    assertEquals("AL", LineBreak.resolvedClass(0xD800), "LB1 reads SG as AL");
    // U+05EB lies in the Hebrew block's unassigned gap, which no range covers,
    // so it takes the @missing XX default.
    assertEquals("XX", LineBreak.rawClass(0x05EB), "an uncovered point is XX");
    assertEquals("AL", LineBreak.resolvedClass(0x05EB), "LB1 reads XX as AL");
    // U+0E31 is SA with General_Category Mn, so LB1 reads it as CM; U+0E01 is
    // SA with category Lo, so LB1 reads it as AL.
    assertEquals("SA", LineBreak.rawClass(0x0E31), "U+0E31 is SA");
    assertEquals("CM", LineBreak.resolvedClass(0x0E31), "LB1 reads SA Mn as CM");
    assertEquals("SA", LineBreak.rawClass(0x0E01), "U+0E01 is SA");
    assertEquals("AL", LineBreak.resolvedClass(0x0E01), "LB1 reads SA Lo as AL");

    // The properties LB19a, LB25, LB30 and LB30b read.
    assertEquals("F", LineBreak.eastAsianWidth(0xFF21), "U+FF21 is Fullwidth");
    assertEquals("Na", LineBreak.eastAsianWidth(0x0041), "U+0041 is Narrow");
    assertTrue(LineBreak.isExtendedPictographic(0x1F466),
        "U+1F466 is Extended_Pictographic");
    assertTrue(!LineBreak.isExtendedPictographic(0x0061),
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
