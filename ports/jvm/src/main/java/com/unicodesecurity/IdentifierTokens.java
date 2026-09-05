package com.unicodesecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * Identifier-shaped tokens of a running-text field.
 *
 * <p>Direct port of {@code Unicode/Security/Identity/IdentifierTokens.lean}. A
 * source line, a chat message or a display name is not one identifier, but the
 * identifier-shaped words inside it are the surface a homoglyph attack targets
 * ({@code scоpe} with a Cyrillic о in {@code let scоpe = 1;}). A token is a
 * maximal run of {@code XID_Continue} codepoints; everything else (space,
 * punctuation, operators, format controls) separates tokens. Each token carries
 * its start position so a finding made on the token can be reported in input
 * coordinates.
 *
 * <p>{@code XID_Continue} is the port's own {@link Security#isXidContinue} over
 * the bundled DerivedCoreProperties.txt.
 */
public final class IdentifierTokens {
  private IdentifierTokens() {}

  /** One identifier-shaped run: its start position in the input and its codepoints. */
  public record Token(int start, List<Integer> cps) {}

  /** The maximal {@code XID_Continue} runs of the input, in input order. */
  public static List<Token> tokens(List<Integer> input) {
    List<Token> out = new ArrayList<>();
    int start = 0;
    List<Integer> current = null;
    for (int idx = 0; idx < input.size(); idx++) {
      int cp = input.get(idx);
      if (Security.isXidContinue(cp)) {
        if (current == null) {
          current = new ArrayList<>();
          start = idx;
        }
        current.add(cp);
      } else if (current != null) {
        out.add(new Token(start, List.copyOf(current)));
        current = null;
      }
    }
    if (current != null) {
      out.add(new Token(start, List.copyOf(current)));
    }
    return List.copyOf(out);
  }

  /** Move token-local positions back into input coordinates. */
  public static List<Integer> shiftPositions(int start, List<Integer> positions) {
    List<Integer> out = new ArrayList<>();
    for (int pos : positions) {
      out.add(pos + start);
    }
    return List.copyOf(out);
  }
}
