package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * Which bidi format controls serve a purpose, and which do not.
 *
 * <p>Direct port of {@code Unicode/Security/Display/BidiControlPurpose.lean}. The
 * nine UAX #9 format controls exist to manage right-to-left text: a span is doing
 * that job when the text it encloses is right-to-left, or when it forces
 * left-to-right text inside a right-to-left context. A span enclosing no strong
 * right-to-left character in a left-to-right context manages nothing ({@code LRI
 * user PDI} around Latin text, {@code LRO return PDF} around a keyword), and an
 * unbalanced control never manages anything. Every Trojan Source payload is a
 * control of that kind; a balanced embedding around an Arabic string literal is
 * the opposite case and renders the literal as written.
 *
 * <p>This is not source-region filtering: the question is asked of every control
 * wherever it sits, and it is decided from the codepoints the span encloses,
 * never from where a tokenizer would place it.
 *
 * <p>Rule, as the Lean {@code walk} states it:
 *
 * <ul>
 *   <li>An opener pushes a span: its position, whether it is an isolate (closed by
 *       PDI) or an embedding/override (closed by PDF), and whether it is
 *       right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
 *       LRI).
 *   <li>Every other codepoint is recorded against the innermost open span only:
 *       strong right-to-left (R or AL), strong left-to-right (L), or ASCII code
 *       syntax. A nested span manages its own content.
 *   <li>PDF closes the top span when it is an embedding; against an isolate on
 *       top, or an empty stack, it is an orphan. PDI closes down to the innermost
 *       isolate, implicitly terminating the embeddings above it, which are
 *       thereby unbalanced; with no isolate open it is an orphan.
 *   <li>A closed span is purposeful iff its direct content is exactly its own
 *       direction and carries no code syntax; a left-to-right span additionally
 *       needs right-to-left context (an enclosing right-to-left span, or a
 *       paragraph whose first strong character is right-to-left).
 *   <li>Reported: every orphan, every opener still open at the end, every
 *       embedding a PDI terminated implicitly, and both ends of every closed span
 *       that was not purposeful.
 * </ul>
 *
 * <p>The strong-direction predicates are the port's own {@link
 * Security#isStrongRtl} / {@link Security#isStrongLtr} over the pinned
 * DerivedBidiClass table.
 */
public final class BidiControlPurpose {
  private BidiControlPurpose() {}

  /** RLE, RLO, RLI, or FSI (whose direction resolves from its content). */
  static boolean opensRtlKind(int cp) {
    return cp == 0x202B || cp == 0x202E || cp == 0x2067 || cp == 0x2068;
  }

  /** LRE, LRO, LRI. */
  static boolean opensLtrKind(int cp) {
    return cp == 0x202A || cp == 0x202D || cp == 0x2066;
  }

  /** LRI, RLI, FSI. */
  static boolean opensIsolateKind(int cp) {
    return cp == 0x2066 || cp == 0x2067 || cp == 0x2068;
  }

  /**
   * The ASCII codepoints a Trojan Source payload moves: quotes, brackets, comment
   * markers, statement separators, operators. Prose punctuation, space and digits
   * are not in the set.
   */
  public static boolean isCodeSyntax(int cp) {
    return switch (cp) {
      case 0x22, 0x27, 0x60, 0x28, 0x29, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x5C, 0x2A,
          0x23, 0x3B, 0x3C, 0x3E, 0x3D, 0x2B, 0x7C, 0x26, 0x25, 0x24, 0x40, 0x5E,
          0x7E -> true;
      default -> false;
    };
  }

  /**
   * UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong character
   * is right-to-left.
   */
  public static boolean paragraphIsRtl(List<Integer> input) {
    for (int cp : input) {
      if (Security.isStrongRtl(cp)) return true;
      if (Security.isStrongLtr(cp)) return false;
    }
    return false;
  }

  /**
   * One open span: where it opened, how it closes, its direction in effect, and
   * what has appeared directly inside it.
   */
  private static final class OpenSpan {
    final int pos;
    final boolean isolate;
    final boolean rtlKind;
    boolean sawRtl;
    boolean sawLtr;
    boolean sawSyntax;

    OpenSpan(int pos, boolean isolate, boolean rtlKind) {
      this.pos = pos;
      this.isolate = isolate;
      this.rtlKind = rtlKind;
    }
  }

  /**
   * A closed span is purposeful iff its direct content is exactly its own
   * direction and carries no code syntax; a left-to-right span additionally needs
   * right-to-left context.
   */
  private static boolean spanPurposeful(OpenSpan s, List<OpenSpan> enclosing, boolean paragraphRtl) {
    if (s.rtlKind) {
      return s.sawRtl && !s.sawLtr && !s.sawSyntax;
    }
    boolean inRtlContext = paragraphRtl;
    for (OpenSpan e : enclosing) {
      if (e.rtlKind) inRtlContext = true;
    }
    return inRtlContext && s.sawLtr && !s.sawRtl && !s.sawSyntax;
  }

  /**
   * Positions of the purposeless bidi format controls in the input, in input
   * order. Empty iff every control is balanced and manages right-to-left text.
   */
  public static List<Integer> purposelessControlPositions(List<Integer> input) {
    boolean paragraphRtl = paragraphIsRtl(input);
    // The stack's last element is the innermost open span.
    List<OpenSpan> stack = new ArrayList<>();
    TreeSet<Integer> reported = new TreeSet<>();

    for (int idx = 0; idx < input.size(); idx++) {
      int cp = input.get(idx);
      if (opensRtlKind(cp) || opensLtrKind(cp)) {
        stack.add(new OpenSpan(idx, opensIsolateKind(cp), opensRtlKind(cp)));
      } else if (cp == 0x202C) {
        // PDF closes the top embedding; an isolate on top or an empty stack makes
        // it an orphan.
        if (stack.isEmpty() || stack.get(stack.size() - 1).isolate) {
          reported.add(idx);
        } else {
          OpenSpan top = stack.remove(stack.size() - 1);
          if (!spanPurposeful(top, stack, paragraphRtl)) {
            reported.add(top.pos);
            reported.add(idx);
          }
        }
      } else if (cp == 0x2069) {
        // PDI closes down to the innermost isolate; the embeddings above it are
        // terminated implicitly and so unbalanced. No isolate open: orphan.
        int isoIndex = -1;
        for (int k = stack.size() - 1; k >= 0; k--) {
          if (stack.get(k).isolate) {
            isoIndex = k;
            break;
          }
        }
        if (isoIndex < 0) {
          reported.add(idx);
        } else {
          for (int k = isoIndex + 1; k < stack.size(); k++) {
            reported.add(stack.get(k).pos);
          }
          OpenSpan closed = stack.get(isoIndex);
          while (stack.size() > isoIndex) {
            stack.remove(stack.size() - 1);
          }
          if (!spanPurposeful(closed, stack, paragraphRtl)) {
            reported.add(closed.pos);
            reported.add(idx);
          }
        }
      } else if (!stack.isEmpty()) {
        OpenSpan top = stack.get(stack.size() - 1);
        top.sawRtl = top.sawRtl || Security.isStrongRtl(cp);
        top.sawLtr = top.sawLtr || Security.isStrongLtr(cp);
        top.sawSyntax = top.sawSyntax || isCodeSyntax(cp);
      }
    }

    // Every opener still open at the end is unbalanced.
    for (OpenSpan open : stack) {
      reported.add(open.pos);
    }

    return List.copyOf(reported);
  }

  /** True iff the input carries at least one purposeless bidi format control. */
  public static boolean hasPurposelessControl(List<Integer> input) {
    return !purposelessControlPositions(input).isEmpty();
  }

  /**
   * Position and codepoint of the first purposeless control as {@code {pos, cp}},
   * or {@code null} when every control is purposeful.
   */
  public static int[] firstPurposelessControl(List<Integer> input) {
    List<Integer> positions = purposelessControlPositions(input);
    if (positions.isEmpty()) return null;
    int pos = positions.get(0);
    return new int[] {pos, input.get(pos)};
  }
}
