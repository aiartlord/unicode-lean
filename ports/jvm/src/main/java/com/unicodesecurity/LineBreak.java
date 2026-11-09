package com.unicodesecurity;

// UAX #14 default line breaking.
//
// A port of the Lean algorithm Unicode.Segmentation.LineBreak.lineBreaks, whose
// lineBreaks_length theorem fixes the output shape: one break-opportunity flag
// per boundary position. The rule order, rule bodies, and snapshot fields below
// mirror that reference -- LB2 through LB31 in UAX #14 R7's canonical order,
// first match winning, the trailing LB31 breaking every otherwise-unmatched
// pair.
//
// Where a line may break is a property of a sequence rather than of a code
// point, so the entry point returns a flag per boundary instead of a predicate
// over code points.
//
// Three mechanisms carry the context the rules read:
//
//   * LB1 is applied at lookup time by resolvedClass, which folds the
//     tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet.
//     SA needs General_Category to choose between CM and AL.
//   * LB9 -- treat X CM* / X ZWJ* as X -- is realised through Snapshot, whose
//     fields hold the most recent class that was not CM or ZWJ. LB10, treating
//     a leftover CM or ZWJ as AL, is the fallback taken when no such class
//     exists.
//   * The rules naming a third character -- LB15b, LB15c, the LB25 bracket and
//     the fourth LB28a sub-rule -- read forward from the position being
//     decided.
//
// Two departures from the Lean. Its positional reads are lits[i]! and cps[i]!,
// panicking accessors; here every read is bounded by the array length the
// caller already holds, so no access can leave the sequence. And its
// spSinceNoSp snapshot field is written by its fold and read by no rule, so
// this port omits it.
//
// Where the Lean carries an optional neighbour, this class carries the value
// beside a presence flag, Java having no option type. A class and the code
// point it came from are set together, so one flag covers the pair.
//
// The four properties the algorithm reads come from LineBreakTables, so this
// class takes code points and reads no file.
public final class LineBreak {
  private LineBreak() {}

  // ── property lookups ──────────────────────────────────────────────────────

  // The index of the one range covering cp, or -1.
  //
  // Each table is sorted by range start and its ranges partition the code
  // space, so the covering range is unique and a binary search finds it.
  private static int rangeIndex(int[] start, int[] end, int cp) {
    int lo = 0;
    int hi = start.length;
    while (lo < hi) {
      int mid = (lo + hi) >>> 1;
      if (cp < start[mid]) {
        hi = mid;
      } else if (cp > end[mid]) {
        lo = mid + 1;
      } else {
        return mid;
      }
    }
    return -1;
  }

  // The raw Line_Break class of cp, before LB1. A code point no range covers is
  // XX, the default LineBreak.txt's own @missing header declares.
  static int rawClassCode(int cp) {
    int index = rangeIndex(
        LineBreakTables.LB_START, LineBreakTables.LB_END, cp);
    return index < 0 ? LineBreakTables.LB_XX : LineBreakTables.LB_CLASS[index];
  }

  // The General_Category of cp, Cn when no range covers it -- the default
  // UnicodeData.txt declares for an unassigned code point.
  static int categoryCode(int cp) {
    int index = rangeIndex(
        LineBreakTables.GC_START, LineBreakTables.GC_END, cp);
    return index < 0 ? LineBreakTables.GC_CN : LineBreakTables.GC_CLASS[index];
  }

  // The East_Asian_Width of cp, N when the file omits it.
  static int widthCode(int cp) {
    int index = rangeIndex(
        LineBreakTables.EAW_START, LineBreakTables.EAW_END, cp);
    return index < 0 ? LineBreakTables.EAW_N : LineBreakTables.EAW_CLASS[index];
  }

  /** The raw Line_Break class of {@code cp} as its UCD property value. */
  public static String rawClass(int cp) {
    return LineBreakTables.LINE_BREAK_CLASSES[rawClassCode(cp)];
  }

  /** The General_Category of {@code cp} as its UCD property value. */
  public static String generalCategory(int cp) {
    return LineBreakTables.GENERAL_CATEGORY_VALUES[categoryCode(cp)];
  }

  /** The East_Asian_Width of {@code cp} as its UCD property value. */
  public static String eastAsianWidth(int cp) {
    return LineBreakTables.EAST_ASIAN_WIDTH_VALUES[widthCode(cp)];
  }

  /** Whether {@code cp} has the Extended_Pictographic property, which LB30b reads. */
  public static boolean isExtendedPictographic(int cp) {
    return rangeIndex(LineBreakTables.EXT_PICT_START,
        LineBreakTables.EXT_PICT_END, cp) >= 0;
  }

  // ── LB1, the tailoring applied at lookup ──────────────────────────────────

  // The Line_Break class cp carries once LB1 has tailored it.
  //
  // AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
  // non-spacing or spacing combining mark and to AL otherwise. Every other
  // class is already in the working alphabet.
  static int resolvedClassCode(int cp) {
    int raw = rawClassCode(cp);
    if (raw == LineBreakTables.LB_AI || raw == LineBreakTables.LB_SG
        || raw == LineBreakTables.LB_XX) {
      return LineBreakTables.LB_AL;
    }
    if (raw == LineBreakTables.LB_CJ) {
      return LineBreakTables.LB_NS;
    }
    if (raw == LineBreakTables.LB_SA) {
      // LB1 reads only the two combining-mark categories here; an enclosing
      // mark is not among them.
      int category = categoryCode(cp);
      return category == LineBreakTables.GC_MN
          || category == LineBreakTables.GC_MC
          ? LineBreakTables.LB_CM
          : LineBreakTables.LB_AL;
    }
    return raw;
  }

  /** The Line_Break class {@code cp} carries once LB1 has tailored it. */
  public static String resolvedClass(int cp) {
    return LineBreakTables.LINE_BREAK_CLASSES[resolvedClassCode(cp)];
  }

  // ── class sets the rules name ─────────────────────────────────────────────

  private static boolean isCmZwj(int cls) {
    return cls == LineBreakTables.LB_CM || cls == LineBreakTables.LB_ZWJ;
  }

  // Whether a preceding class blocks LB9's absorption, so a following CM or ZWJ
  // stands on its own and LB10 reads it as AL.
  private static boolean blocksAbsorb(int cls) {
    return cls == LineBreakTables.LB_BK || cls == LineBreakTables.LB_CR
        || cls == LineBreakTables.LB_LF || cls == LineBreakTables.LB_NL
        || cls == LineBreakTables.LB_SP || cls == LineBreakTables.LB_ZW;
  }

  // Whether the class is QU and the code point is initial punctuation, the
  // refinement LB15a reads.
  private static boolean isPiQuote(int cp, int cls) {
    return cls == LineBreakTables.LB_QU
        && categoryCode(cp) == LineBreakTables.GC_PI;
  }

  // Whether the class is QU and the code point is final punctuation, the
  // refinement LB15b reads.
  private static boolean isPfQuote(int cp, int cls) {
    return cls == LineBreakTables.LB_QU
        && categoryCode(cp) == LineBreakTables.GC_PF;
  }

  // U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0 moved
  // it from class HY to class HH.
  private static final int HYPHEN = 0x2010;

  // U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
  private static final int DOTTED_CIRCLE = 0x25CC;

  // Whether cp is East_Asian_Width F, W or H, the set LB25 and LB30 read.
  private static boolean isEastAsianFullWide(int cp) {
    int width = widthCode(cp);
    return width == LineBreakTables.EAW_F || width == LineBreakTables.EAW_W
        || width == LineBreakTables.EAW_H;
  }

  // Whether cp counts as East Asian for LB19a's tailoring, which treats
  // Ambiguous as East Asian alongside Fullwidth, Wide and Halfwidth.
  private static boolean isEastAsianOrAmbiguous(int cp) {
    int width = widthCode(cp);
    return width == LineBreakTables.EAW_F || width == LineBreakTables.EAW_W
        || width == LineBreakTables.EAW_H || width == LineBreakTables.EAW_A;
  }

  // Whether the effective class is present and among classes.
  private static boolean effIn(int effective, boolean present, int... classes) {
    if (!present) {
      return false;
    }
    for (int cls : classes) {
      if (effective == cls) {
        return true;
      }
    }
    return false;
  }

  // ── the left-hand context a boundary decision reads ───────────────────────

  // The classes and code points of the most recent characters LB9 did not
  // absorb, plus the running counters the rules keep. Mirrors the Lean
  // EffSnapshot.
  private static final class Snapshot {
    // Class of the most recent character that was not CM or ZWJ, and its code
    // point -- LB20a, LB21a and LB28a name U+2010 and U+25CC. hasEffPrev covers
    // both, since advance sets them together.
    private int effPrev;
    private int effPrevCp;
    private boolean hasEffPrev;

    // Class of the most recent character that was not CM, ZWJ or SP.
    private int effPrevNoSp;
    private boolean hasEffPrevNoSp;

    // Class of the second most recent such character, and its code point.
    private int effPrevPrev;
    private int effPrevPrevCp;
    private boolean hasEffPrevPrev;

    // Whether an LB15a initial-punctuation quote window is open.
    private boolean inPiQuoteWindow;
    // Length of the current regional-indicator run, for LB30a.
    private int riRun;
    // Whether an LB25 numeric chain is open.
    private boolean inNuChain;
  }

  // The class a CM or ZWJ takes from what it attaches to under LB9, or AL under
  // LB10 when nothing absorbs it.
  private static int effectiveClass(int cls, int effPrev, boolean hasEffPrev) {
    if (!isCmZwj(cls)) {
      return cls;
    }
    if (!hasEffPrev) {
      return LineBreakTables.LB_AL;
    }
    return blocksAbsorb(effPrev) ? LineBreakTables.LB_AL : cls;
  }

  // Fold one character into the context. A character LB9 absorbs leaves the
  // context untouched, which is what makes the neighbours it records effective
  // rather than literal. Mirrors the Lean buildSnapshots step.
  private static Snapshot advance(Snapshot s, int cp, int cls) {
    int effective = effectiveClass(cls, s.effPrev, s.hasEffPrev);
    if (isCmZwj(effective)) {
      return s;
    }

    // LB15a opens its window only where an initial-punctuation quote stands
    // outside a word; a space carries an open window forward.
    boolean leftContextOpens = !s.hasEffPrev
        || effIn(s.effPrev, s.hasEffPrev, LineBreakTables.LB_BK,
            LineBreakTables.LB_CR, LineBreakTables.LB_LF,
            LineBreakTables.LB_NL, LineBreakTables.LB_OP,
            LineBreakTables.LB_QU, LineBreakTables.LB_GL,
            LineBreakTables.LB_SP, LineBreakTables.LB_ZW);
    boolean inPiQuoteWindow = false;
    if (isPiQuote(cp, effective) && leftContextOpens) {
      inPiQuoteWindow = true;
    } else if (effective == LineBreakTables.LB_SP) {
      inPiQuoteWindow = s.inPiQuoteWindow;
    }

    boolean inNuChain = false;
    if (effective == LineBreakTables.LB_NU) {
      inNuChain = true;
    } else if (s.inNuChain) {
      inNuChain = effective == LineBreakTables.LB_SY
          || effective == LineBreakTables.LB_IS
          || effective == LineBreakTables.LB_CL
          || effective == LineBreakTables.LB_CP
          || effective == LineBreakTables.LB_PR;
    }

    Snapshot out = new Snapshot();
    out.effPrev = effective;
    out.effPrevCp = cp;
    out.hasEffPrev = true;
    out.effPrevPrev = s.effPrev;
    out.effPrevPrevCp = s.effPrevCp;
    out.hasEffPrevPrev = s.hasEffPrev;
    out.inPiQuoteWindow = inPiQuoteWindow;
    out.inNuChain = inNuChain;
    if (effective == LineBreakTables.LB_SP) {
      out.effPrevNoSp = s.effPrevNoSp;
      out.hasEffPrevNoSp = s.hasEffPrevNoSp;
    } else {
      out.effPrevNoSp = effective;
      out.hasEffPrevNoSp = true;
    }
    out.riRun = effective == LineBreakTables.LB_RI ? s.riRun + 1 : 0;
    return out;
  }

  // ── lookahead ─────────────────────────────────────────────────────────────

  // Whether the class at index is cls, false past the end of the sequence.
  private static boolean classAtIs(int[] classes, int index, int cls) {
    return index < classes.length && classes[index] == cls;
  }

  // LB15b holds when the final quote is last, or when what follows it cannot
  // itself open a line.
  private static boolean finalQuoteCloses(int[] classes, int index) {
    if (index >= classes.length) {
      return true;
    }
    int next = classes[index];
    return next == LineBreakTables.LB_SP || next == LineBreakTables.LB_GL
        || next == LineBreakTables.LB_WJ || next == LineBreakTables.LB_CL
        || next == LineBreakTables.LB_QU || next == LineBreakTables.LB_CP
        || next == LineBreakTables.LB_EX || next == LineBreakTables.LB_IS
        || next == LineBreakTables.LB_SY || next == LineBreakTables.LB_BK
        || next == LineBreakTables.LB_CR || next == LineBreakTables.LB_LF
        || next == LineBreakTables.LB_NL || next == LineBreakTables.LB_ZW;
  }

  // The fourth LB28a sub-rule looks past any CM or ZWJ the cluster absorbs, so
  // the character it tests is the first significant one ahead.
  private static boolean nextSignificantIsVf(int[] classes, int index) {
    for (int i = index; i < classes.length; i++) {
      if (!isCmZwj(classes[i])) {
        return classes[i] == LineBreakTables.LB_VF;
      }
    }
    return false;
  }

  // ── the rule cascade ──────────────────────────────────────────────────────

  // Whether a line break opportunity falls immediately before index, given the
  // character before it and the context accumulated from everything earlier.
  private static boolean breaksBefore(
      int[] cps, int[] classes, int index, Snapshot s) {
    if (index >= cps.length) {
      return true; // LB3
    }
    int prevCp = cps[index - 1];
    int prevClass = classes[index - 1];
    int currentCp = cps[index];
    int currentClass = classes[index];
    int ahead = index + 1;

    int eff = effectiveClass(currentClass, s.effPrev, s.hasEffPrev);
    int left = isCmZwj(prevClass) ? s.effPrev : prevClass;
    boolean hasLeft = isCmZwj(prevClass) ? s.hasEffPrev : true;

    // LB4
    if (prevClass == LineBreakTables.LB_BK) {
      return true;
    }
    // LB5
    if (prevClass == LineBreakTables.LB_CR
        && currentClass == LineBreakTables.LB_LF) {
      return false;
    }
    if (prevClass == LineBreakTables.LB_CR || prevClass == LineBreakTables.LB_LF
        || prevClass == LineBreakTables.LB_NL) {
      return true;
    }
    // LB6
    if (currentClass == LineBreakTables.LB_BK
        || currentClass == LineBreakTables.LB_CR
        || currentClass == LineBreakTables.LB_LF
        || currentClass == LineBreakTables.LB_NL) {
      return false;
    }
    // LB7
    if (currentClass == LineBreakTables.LB_SP
        || currentClass == LineBreakTables.LB_ZW) {
      return false;
    }
    // LB8
    if (s.hasEffPrevNoSp && s.effPrevNoSp == LineBreakTables.LB_ZW) {
      return true;
    }
    // LB8a
    if (prevClass == LineBreakTables.LB_ZWJ) {
      return false;
    }
    // LB9
    if (isCmZwj(currentClass) && s.hasEffPrev && !blocksAbsorb(s.effPrev)) {
      return false;
    }
    // LB11
    if (eff == LineBreakTables.LB_WJ
        || effIn(left, hasLeft, LineBreakTables.LB_WJ)) {
      return false;
    }
    // LB12
    if (effIn(left, hasLeft, LineBreakTables.LB_GL)) {
      return false;
    }
    // LB12a
    if (eff == LineBreakTables.LB_GL
        && !effIn(left, hasLeft, LineBreakTables.LB_SP, LineBreakTables.LB_BA,
            LineBreakTables.LB_HY, LineBreakTables.LB_HH)) {
      return false;
    }
    // LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS
    // that opens a number and follows a space, as in "equals .35".
    if (prevClass == LineBreakTables.LB_SP && eff == LineBreakTables.LB_IS
        && classAtIs(classes, ahead, LineBreakTables.LB_NU)) {
      return true;
    }
    // LB13
    if (eff == LineBreakTables.LB_CL || eff == LineBreakTables.LB_CP
        || eff == LineBreakTables.LB_EX || eff == LineBreakTables.LB_IS
        || eff == LineBreakTables.LB_SY) {
      return false;
    }
    // LB14
    if (s.hasEffPrevNoSp && s.effPrevNoSp == LineBreakTables.LB_OP) {
      return false;
    }
    // LB15a
    if (s.inPiQuoteWindow) {
      return false;
    }
    // LB15b
    if (isPfQuote(currentCp, eff) && finalQuoteCloses(classes, ahead)) {
      return false;
    }
    // LB15d
    if (eff == LineBreakTables.LB_IS) {
      return false;
    }
    // LB16
    if (eff == LineBreakTables.LB_NS && s.hasEffPrevNoSp
        && (s.effPrevNoSp == LineBreakTables.LB_CL
            || s.effPrevNoSp == LineBreakTables.LB_CP)) {
      return false;
    }
    // LB17
    if (eff == LineBreakTables.LB_B2 && s.hasEffPrevNoSp
        && s.effPrevNoSp == LineBreakTables.LB_B2) {
      return false;
    }
    // LB18
    if (prevClass == LineBreakTables.LB_SP) {
      return true;
    }
    // LB19 and LB19a. A quote neither breaks before nor after, except on the
    // OUTER side of an initial or final punctuation quote standing in
    // contiguous East Asian content -- there the default break applies, so a
    // line may break at the quote boundary. The inner side stays unbroken,
    // being the boundary inside the quote's own scope.
    if (eff == LineBreakTables.LB_QU) {
      boolean nextEastAsian =
          ahead < cps.length && isEastAsianOrAmbiguous(cps[ahead]);
      boolean openQuoteInEastAsian = isPiQuote(currentCp, eff)
          && isEastAsianOrAmbiguous(prevCp)
          && isEastAsianOrAmbiguous(currentCp) && nextEastAsian;
      if (!openQuoteInEastAsian) {
        return false;
      }
    }
    if (effIn(left, hasLeft, LineBreakTables.LB_QU)) {
      boolean closeQuoteInEastAsian = false;
      if (s.hasEffPrev) {
        int quoteCp = s.effPrevCp;
        closeQuoteInEastAsian = isPfQuote(quoteCp, LineBreakTables.LB_QU)
            && s.hasEffPrevPrev
            && isEastAsianOrAmbiguous(s.effPrevPrevCp)
            && isEastAsianOrAmbiguous(quoteCp)
            && isEastAsianOrAmbiguous(currentCp);
      }
      if (!closeQuoteInEastAsian) {
        return false;
      }
    }
    // LB20
    if (eff == LineBreakTables.LB_CB
        || effIn(left, hasLeft, LineBreakTables.LB_CB)) {
      return true;
    }

    // LB20.1 and LB20a both require the hyphen's own left context to be outside
    // a word, the same start-of-segment set.
    boolean hyphenLeftContextOpens = !s.hasEffPrevPrev
        || effIn(s.effPrevPrev, s.hasEffPrevPrev, LineBreakTables.LB_BK,
            LineBreakTables.LB_CR, LineBreakTables.LB_LF,
            LineBreakTables.LB_NL, LineBreakTables.LB_SP,
            LineBreakTables.LB_ZW, LineBreakTables.LB_CB,
            LineBreakTables.LB_GL);
    // LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
    // its own left context is outside a word. A mid-word HH falls through to
    // LB31.
    if (effIn(left, hasLeft, LineBreakTables.LB_HH)
        && (eff == LineBreakTables.LB_AL || eff == LineBreakTables.LB_HL)
        && hyphenLeftContextOpens) {
      return false;
    }
    // LB20a, with UCD 17.0's right side broadened to HL beside AL.
    if (eff == LineBreakTables.LB_AL || eff == LineBreakTables.LB_HL) {
      boolean hyphenCarriesLeft = s.hasEffPrev
          && (s.effPrev == LineBreakTables.LB_HY
              || s.effPrev == LineBreakTables.LB_HH
              || s.effPrevCp == HYPHEN);
      if (hyphenCarriesLeft && hyphenLeftContextOpens) {
        return false;
      }
    }
    // LB21
    if (eff == LineBreakTables.LB_BA || eff == LineBreakTables.LB_HY
        || eff == LineBreakTables.LB_HH || eff == LineBreakTables.LB_NS) {
      return false;
    }
    if (effIn(left, hasLeft, LineBreakTables.LB_BB)) {
      return false;
    }
    // LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what comes
    // next unless that is itself HL. A BA does not glue here.
    if (s.hasEffPrevPrev && s.effPrevPrev == LineBreakTables.LB_HL
        && eff != LineBreakTables.LB_HL && s.hasEffPrev
        && (s.effPrev == LineBreakTables.LB_HY || s.effPrevCp == HYPHEN)) {
      return false;
    }
    // LB21b
    if (eff == LineBreakTables.LB_HL
        && effIn(left, hasLeft, LineBreakTables.LB_SY)) {
      return false;
    }
    // LB22
    if (eff == LineBreakTables.LB_IN) {
      return false;
    }
    // LB23
    if (eff == LineBreakTables.LB_NU
        && effIn(left, hasLeft, LineBreakTables.LB_AL,
            LineBreakTables.LB_HL)) {
      return false;
    }
    if ((eff == LineBreakTables.LB_AL || eff == LineBreakTables.LB_HL)
        && effIn(left, hasLeft, LineBreakTables.LB_NU)) {
      return false;
    }
    // LB23a
    if ((eff == LineBreakTables.LB_ID || eff == LineBreakTables.LB_EB
        || eff == LineBreakTables.LB_EM)
        && effIn(left, hasLeft, LineBreakTables.LB_PR)) {
      return false;
    }
    if (eff == LineBreakTables.LB_PO
        && effIn(left, hasLeft, LineBreakTables.LB_ID, LineBreakTables.LB_EB,
            LineBreakTables.LB_EM)) {
      return false;
    }
    // LB24
    if ((eff == LineBreakTables.LB_AL || eff == LineBreakTables.LB_HL)
        && effIn(left, hasLeft, LineBreakTables.LB_PR,
            LineBreakTables.LB_PO)) {
      return false;
    }
    if ((eff == LineBreakTables.LB_PR || eff == LineBreakTables.LB_PO)
        && effIn(left, hasLeft, LineBreakTables.LB_AL,
            LineBreakTables.LB_HL)) {
      return false;
    }
    // LB25, closing an open numeric chain with a CL or CP suffix and a following
    // PO or PR.
    if (s.inNuChain
        && (eff == LineBreakTables.LB_CL || eff == LineBreakTables.LB_CP
            || eff == LineBreakTables.LB_PO || eff == LineBreakTables.LB_PR)) {
      return false;
    }
    // LB25, opening a chain
    if (eff == LineBreakTables.LB_NU
        && effIn(left, hasLeft, LineBreakTables.LB_PR, LineBreakTables.LB_PO,
            LineBreakTables.LB_HY, LineBreakTables.LB_OP,
            LineBreakTables.LB_IS)) {
      return false;
    }
    // LB25, chain body
    if (eff == LineBreakTables.LB_NU
        && effIn(left, hasLeft, LineBreakTables.LB_NU)) {
      return false;
    }
    // LB25, extending an open chain across a SY
    if (eff == LineBreakTables.LB_NU
        && effIn(left, hasLeft, LineBreakTables.LB_SY) && s.inNuChain) {
      return false;
    }
    // LB25, bracketed prefix: a PR joins an OP only when the OP itself opens a
    // number, and neither is East Asian Fullwidth, Wide or Halfwidth.
    if (eff == LineBreakTables.LB_OP
        && effIn(left, hasLeft, LineBreakTables.LB_PR)
        && !isEastAsianFullWide(currentCp) && s.hasEffPrev
        && !isEastAsianFullWide(s.effPrevCp)
        && classAtIs(classes, ahead, LineBreakTables.LB_NU)) {
      return false;
    }
    // LB26
    if (effIn(left, hasLeft, LineBreakTables.LB_JL)
        && (eff == LineBreakTables.LB_JL || eff == LineBreakTables.LB_JV
            || eff == LineBreakTables.LB_H2 || eff == LineBreakTables.LB_H3)) {
      return false;
    }
    if (effIn(left, hasLeft, LineBreakTables.LB_JV, LineBreakTables.LB_H2)
        && (eff == LineBreakTables.LB_JV || eff == LineBreakTables.LB_JT)) {
      return false;
    }
    if (effIn(left, hasLeft, LineBreakTables.LB_JT, LineBreakTables.LB_H3)
        && eff == LineBreakTables.LB_JT) {
      return false;
    }
    // LB27
    if (effIn(left, hasLeft, LineBreakTables.LB_JL, LineBreakTables.LB_JV,
        LineBreakTables.LB_JT, LineBreakTables.LB_H2, LineBreakTables.LB_H3)
        && (eff == LineBreakTables.LB_IN || eff == LineBreakTables.LB_PO)) {
      return false;
    }
    if (effIn(left, hasLeft, LineBreakTables.LB_PR)
        && (eff == LineBreakTables.LB_JL || eff == LineBreakTables.LB_JV
            || eff == LineBreakTables.LB_JT || eff == LineBreakTables.LB_H2
            || eff == LineBreakTables.LB_H3)) {
      return false;
    }
    // LB28
    if ((eff == LineBreakTables.LB_AL || eff == LineBreakTables.LB_HL)
        && effIn(left, hasLeft, LineBreakTables.LB_AL,
            LineBreakTables.LB_HL)) {
      return false;
    }

    // LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class AL and
    // stands in for a cluster base throughout.
    boolean leftIsAksaraBase =
        effIn(left, hasLeft, LineBreakTables.LB_AK, LineBreakTables.LB_AS)
            || (s.hasEffPrev && s.effPrevCp == DOTTED_CIRCLE
                && s.effPrev == LineBreakTables.LB_AL);
    if (effIn(left, hasLeft, LineBreakTables.LB_AP)
        && (eff == LineBreakTables.LB_AK || eff == LineBreakTables.LB_AS
            || currentCp == DOTTED_CIRCLE)) {
      return false;
    }
    if (leftIsAksaraBase
        && (eff == LineBreakTables.LB_VF || eff == LineBreakTables.LB_VI)) {
      return false;
    }
    if (s.hasEffPrev && s.effPrev == LineBreakTables.LB_VI
        && (effIn(s.effPrevPrev, s.hasEffPrevPrev, LineBreakTables.LB_AK,
            LineBreakTables.LB_AS)
            || (s.hasEffPrevPrev && s.effPrevPrevCp == DOTTED_CIRCLE))
        && (eff == LineBreakTables.LB_AK || currentCp == DOTTED_CIRCLE)) {
      return false;
    }
    if (leftIsAksaraBase
        && (eff == LineBreakTables.LB_AK || eff == LineBreakTables.LB_AS
            || currentCp == DOTTED_CIRCLE)
        && nextSignificantIsVf(classes, ahead)) {
      return false;
    }
    // LB29
    if ((eff == LineBreakTables.LB_AL || eff == LineBreakTables.LB_HL)
        && effIn(left, hasLeft, LineBreakTables.LB_IS)) {
      return false;
    }
    // LB30, where the bracket must not be East Asian Fullwidth, Wide or
    // Halfwidth.
    if (eff == LineBreakTables.LB_OP
        && effIn(left, hasLeft, LineBreakTables.LB_AL, LineBreakTables.LB_HL,
            LineBreakTables.LB_NU)
        && !isEastAsianFullWide(currentCp)) {
      return false;
    }
    if ((eff == LineBreakTables.LB_AL || eff == LineBreakTables.LB_HL
        || eff == LineBreakTables.LB_NU)
        && effIn(left, hasLeft, LineBreakTables.LB_CP)
        && !isEastAsianFullWide(prevCp)) {
      return false;
    }
    // LB30a
    if (eff == LineBreakTables.LB_RI && s.riRun % 2 == 1) {
      return false;
    }
    // LB30b
    if (eff == LineBreakTables.LB_EM
        && effIn(left, hasLeft, LineBreakTables.LB_EB)) {
      return false;
    }
    if (eff == LineBreakTables.LB_EM && s.hasEffPrev
        && isExtendedPictographic(s.effPrevCp)
        && categoryCode(s.effPrevCp) == LineBreakTables.GC_CN) {
      return false;
    }
    // LB31
    return true;
  }

  // ── entry points ──────────────────────────────────────────────────────────

  /**
   * One break-opportunity flag per boundary of the code point sequence, so a
   * sequence of n code points yields n + 1 flags -- the shape the Lean
   * lineBreaks_length theorem fixes.
   *
   * <p>Entry 0 is false -- LB2 forbids a break at the start of text -- and
   * entry n is true per LB3, which requires one at the end.
   */
  public static boolean[] lineBreaks(int[] cps) {
    int[] classes = new int[cps.length];
    for (int i = 0; i < cps.length; i++) {
      classes[i] = resolvedClassCode(cps[i]);
    }
    boolean[] out = new boolean[cps.length + 1];
    Snapshot s = new Snapshot();
    for (int i = 0; i < cps.length; i++) {
      out[i] = i == 0 ? false : breaksBefore(cps, classes, i, s);
      s = advance(s, cps[i], classes[i]);
    }
    out[cps.length] = true; // LB3
    return out;
  }

  /**
   * The code point sequence split at every break opportunity -- the runs a
   * renderer may place on separate lines.
   */
  public static int[][] lineRuns(int[] cps) {
    boolean[] breaks = lineBreaks(cps);
    int runs = 0;
    for (int i = 0; i < cps.length; i++) {
      if (breaks[i + 1]) {
        runs++;
      }
    }
    int[][] out = new int[runs][];
    int at = 0;
    int start = 0;
    for (int i = 0; i < cps.length; i++) {
      if (breaks[i + 1]) {
        int[] run = new int[i + 1 - start];
        System.arraycopy(cps, start, run, 0, run.length);
        out[at++] = run;
        start = i + 1;
      }
    }
    return out;
  }
}
