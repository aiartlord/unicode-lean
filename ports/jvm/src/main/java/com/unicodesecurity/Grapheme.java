package com.unicodesecurity;

// UAX #29 default extended grapheme cluster segmentation.
//
// A transcription of the Lean algorithm
// Unicode.Segmentation.GraphemeBreak.graphemeBreaks, whose graphemeBreaks_eq_spec
// theorem relates it to the declarative UAX #29 GB1-GB999 specification. The
// state fields, rule order and transitions below mirror that reference: the
// first matching rule wins, and the trailing GB999 breaks every
// otherwise-unmatched pair.
//
// Where a cluster boundary falls is a property of a sequence rather than of a
// code point, so the entry point returns one flag per boundary position: a
// sequence of n code points yields n + 1 flags, entry 0 the GB1 start-of-text
// break and entry n the GB2 end-of-text break, both always true.
//
// Three pieces of left context carry what the rules read, each a field of
// State: the previous code point's class, the GB11 emoji-pictograph window,
// and the GB9c Indic-conjunct window, plus the regional-indicator run length
// GB12 and GB13 count parity over.
//
// The three properties come from the generated tables in GraphemeTables, so
// this class takes code points and needs no data directory.
final class Grapheme {
  private Grapheme() {}

  // The GB11 left-context window: whether the scan has just passed an
  // Extended_Pictographic, and whether a ZWJ has followed it.
  private static final int EPIC_NONE = 0;
  private static final int EPIC_AFTER_EP = 1;
  private static final int EPIC_AFTER_EP_ZWJ = 2;

  // The GB9c left-context window: whether the scan has passed an
  // Indic_Conjunct_Break consonant, and whether a linker has followed it.
  private static final int INCB_STATE_NONE = 0;
  private static final int INCB_STATE_CONSONANT = 1;
  private static final int INCB_STATE_LINKER = 2;

  // The class of the previous code point before the first one is read. No
  // table entry carries it, so it cannot collide with a real class.
  private static final int NO_PREVIOUS = -1;

  // The running scan state, mirroring the Lean State.
  private static final class State {
    int prevClass = NO_PREVIOUS;
    int epicState = EPIC_NONE;
    int incbState = INCB_STATE_NONE;
    int riRun = 0;
  }

  // The class of the one range covering cp, or the property's default when no
  // range does. Each table is sorted by range start and its ranges are
  // disjoint, so the covering range is unique and a binary search finds it.
  private static int classOf(int[] start, int[] end, byte[] cls, int cp, int fallback) {
    int low = 0;
    int high = start.length;
    while (low < high) {
      int mid = low + ((high - low) >>> 1);
      if (cp < start[mid]) {
        high = mid;
      } else if (cp > end[mid]) {
        low = mid + 1;
      } else {
        return cls[mid];
      }
    }
    return fallback;
  }

  private static boolean inRanges(int[] start, int[] end, int cp) {
    int low = 0;
    int high = start.length;
    while (low < high) {
      int mid = low + ((high - low) >>> 1);
      if (cp < start[mid]) {
        high = mid;
      } else if (cp > end[mid]) {
        low = mid + 1;
      } else {
        return true;
      }
    }
    return false;
  }

  // Grapheme_Cluster_Break of cp, GCB_OTHER when no range covers it.
  static int lookupGcb(int cp) {
    return classOf(
        GraphemeTables.GCB_START,
        GraphemeTables.GCB_END,
        GraphemeTables.GCB_CLASS,
        cp,
        GraphemeTables.GCB_OTHER);
  }

  // Indic_Conjunct_Break of cp, INCB_NONE when no range covers it.
  static int lookupIncb(int cp) {
    return classOf(
        GraphemeTables.INCB_START,
        GraphemeTables.INCB_END,
        GraphemeTables.INCB_CLASS,
        cp,
        GraphemeTables.INCB_NONE);
  }

  // Whether cp carries the Extended_Pictographic property, which GB11 reads.
  static boolean isExtendedPictographic(int cp) {
    return inRanges(GraphemeTables.EXT_PICT_START, GraphemeTables.EXT_PICT_END, cp);
  }

  // Whether a cluster boundary falls immediately before cp, given the running
  // state. UAX #29 GB1 through GB999 in canonical order.
  private static boolean shouldBreakBefore(int cp, State s) {
    if (s.prevClass == NO_PREVIOUS) {
      return true; // GB1: start of text
    }
    int bc = lookupGcb(cp);
    int incb = lookupIncb(cp);
    boolean isEp = isExtendedPictographic(cp);
    int pc = s.prevClass;

    if (pc == GraphemeTables.GCB_CR && bc == GraphemeTables.GCB_LF) {
      return false; // GB3: CR x LF
    }
    if (pc == GraphemeTables.GCB_CONTROL
        || pc == GraphemeTables.GCB_CR
        || pc == GraphemeTables.GCB_LF) {
      return true; // GB4: (Control | CR | LF) divides
    }
    if (bc == GraphemeTables.GCB_CONTROL
        || bc == GraphemeTables.GCB_CR
        || bc == GraphemeTables.GCB_LF) {
      return true; // GB5: divides (Control | CR | LF)
    }
    if (pc == GraphemeTables.GCB_L
        && (bc == GraphemeTables.GCB_L
            || bc == GraphemeTables.GCB_V
            || bc == GraphemeTables.GCB_LV
            || bc == GraphemeTables.GCB_LVT)) {
      return false; // GB6: L x (L | V | LV | LVT)
    }
    if ((pc == GraphemeTables.GCB_LV || pc == GraphemeTables.GCB_V)
        && (bc == GraphemeTables.GCB_V || bc == GraphemeTables.GCB_T)) {
      return false; // GB7: (LV | V) x (V | T)
    }
    if ((pc == GraphemeTables.GCB_LVT || pc == GraphemeTables.GCB_T)
        && bc == GraphemeTables.GCB_T) {
      return false; // GB8: (LVT | T) x T
    }
    if (bc == GraphemeTables.GCB_EXTEND || bc == GraphemeTables.GCB_ZWJ) {
      return false; // GB9: x (Extend | ZWJ)
    }
    if (bc == GraphemeTables.GCB_SPACING_MARK) {
      return false; // GB9a: x SpacingMark
    }
    if (pc == GraphemeTables.GCB_PREPEND) {
      return false; // GB9b: Prepend x
    }
    if (s.incbState == INCB_STATE_LINKER && incb == GraphemeTables.INCB_CONSONANT) {
      // GB9c: Consonant (Extend | Linker)* Linker (Extend | Linker)* x Consonant
      return false;
    }
    if (s.epicState == EPIC_AFTER_EP_ZWJ && isEp) {
      return false; // GB11: ExtPict Extend* ZWJ x ExtPict
    }
    if (bc == GraphemeTables.GCB_REGIONAL_INDICATOR && (s.riRun % 2) == 1) {
      return false; // GB12 / GB13: an odd-parity regional-indicator run extends
    }
    return true; // GB999: any divides any
  }

  // The state after consuming cp. Mirrors the Lean advance.
  private static void advance(int cp, State s) {
    int bc = lookupGcb(cp);
    int incb = lookupIncb(cp);
    boolean isEp = isExtendedPictographic(cp);

    int epic;
    if (isEp) {
      epic = EPIC_AFTER_EP;
    } else if (s.epicState == EPIC_AFTER_EP && bc == GraphemeTables.GCB_EXTEND) {
      epic = EPIC_AFTER_EP;
    } else if (s.epicState == EPIC_AFTER_EP && bc == GraphemeTables.GCB_ZWJ) {
      epic = EPIC_AFTER_EP_ZWJ;
    } else {
      epic = EPIC_NONE;
    }

    int incbState;
    if (incb == GraphemeTables.INCB_CONSONANT) {
      incbState = INCB_STATE_CONSONANT;
    } else if (s.incbState == INCB_STATE_CONSONANT && incb == GraphemeTables.INCB_LINKER) {
      incbState = INCB_STATE_LINKER;
    } else if (s.incbState == INCB_STATE_CONSONANT && incb == GraphemeTables.INCB_EXTEND) {
      incbState = INCB_STATE_CONSONANT;
    } else if (s.incbState == INCB_STATE_LINKER && incb == GraphemeTables.INCB_LINKER) {
      incbState = INCB_STATE_LINKER;
    } else if (s.incbState == INCB_STATE_LINKER && incb == GraphemeTables.INCB_EXTEND) {
      incbState = INCB_STATE_LINKER;
    } else {
      incbState = INCB_STATE_NONE;
    }

    s.riRun = bc == GraphemeTables.GCB_REGIONAL_INDICATOR ? s.riRun + 1 : 0;
    s.prevClass = bc;
    s.epicState = epic;
    s.incbState = incbState;
  }

  // One boundary flag per position, so a sequence of n code points yields
  // n + 1 flags. Entry 0 is the GB1 start-of-text break and entry n the GB2
  // end-of-text break, both always true.
  static boolean[] graphemeBreaks(int[] cps) {
    boolean[] breaks = new boolean[cps.length + 1];
    State s = new State();
    for (int i = 0; i < cps.length; i++) {
      breaks[i] = shouldBreakBefore(cps[i], s);
      advance(cps[i], s);
    }
    breaks[cps.length] = true; // GB2
    return breaks;
  }

  // The code points between consecutive boundaries — the clusters a renderer
  // treats as single user-perceived characters.
  static int[][] graphemeClusters(int[] cps) {
    boolean[] breaks = graphemeBreaks(cps);
    int clusterCount = 0;
    for (int i = 0; i < cps.length; i++) {
      if (breaks[i]) {
        clusterCount++;
      }
    }
    int[][] clusters = new int[clusterCount][];
    int at = -1;
    int start = 0;
    for (int i = 0; i < cps.length; i++) {
      if (breaks[i]) {
        if (at >= 0) {
          clusters[at] = java.util.Arrays.copyOfRange(cps, start, i);
        }
        at++;
        start = i;
      }
    }
    if (at >= 0) {
      clusters[at] = java.util.Arrays.copyOfRange(cps, start, cps.length);
    }
    return clusters;
  }
}
