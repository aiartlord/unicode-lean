namespace UnicodeSecurity;

// identifier-tokens — identifier-shaped tokens of a running-text field.
//
// Direct port of Unicode/Security/Identity/IdentifierTokens.lean. A source
// line, a chat message or a display name is not one identifier, but the
// identifier-shaped words inside it are the surface a homoglyph attack targets
// (scоpe with a Cyrillic о in `let scоpe = 1;`). A token is a maximal run of
// XID_Continue codepoints; everything else (space, punctuation, operators,
// format controls) separates tokens. Each token carries its start position so a
// finding made on the token can be reported in input coordinates.
//
// XID_Continue is the port's own IsXidContinue over the bundled
// DerivedCoreProperties.txt.
public static partial class Security
{
    public static class IdentifierTokens
    {
        /// <summary>One identifier-shaped run: its start position in the input
        /// and its codepoints.</summary>
        public sealed record Token(int Start, List<int> Cps);

        /// <summary>The maximal XID_Continue runs of the input, in input
        /// order.</summary>
        public static List<Token> Tokens(IReadOnlyList<int> input)
        {
            var tokens = new List<Token>();
            var start = 0;
            List<int>? current = null;
            for (var idx = 0; idx < input.Count; idx++)
            {
                var cp = input[idx];
                if (Security.IsXidContinue(cp))
                {
                    if (current is null)
                    {
                        current = new List<int>();
                        start = idx;
                    }
                    current.Add(cp);
                }
                else if (current is not null)
                {
                    tokens.Add(new Token(start, current));
                    current = null;
                }
            }
            if (current is not null)
            {
                tokens.Add(new Token(start, current));
            }
            return tokens;
        }

        /// <summary>Move token-local positions back into input
        /// coordinates.</summary>
        public static List<int> ShiftPositions(int start, IReadOnlyList<int> positions) =>
            positions.Select(p => p + start).ToList();
    }
}
