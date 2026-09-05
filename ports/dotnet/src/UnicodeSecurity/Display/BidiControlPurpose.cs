namespace UnicodeSecurity;

// bidi-control-purpose — which bidi format controls serve a purpose, and which
// do not.
//
// Direct port of Unicode/Security/Display/BidiControlPurpose.lean. The nine
// UAX #9 format controls exist to manage right-to-left text: a span is doing
// that job when the text it encloses is right-to-left, or when it forces
// left-to-right text inside a right-to-left context. A span enclosing no strong
// right-to-left character in a left-to-right context manages nothing (LRI user
// PDI around Latin text, LRO return PDF around a keyword), and an unbalanced
// control never manages anything. Every Trojan Source payload is a control of
// that kind; a balanced embedding around an Arabic string literal is the
// opposite case and renders the literal as written.
//
// This is not source-region filtering: the question is asked of every control
// wherever it sits, and it is decided from the codepoints the span encloses,
// never from where a tokenizer would place it.
//
// Rule, as the Lean walk states it:
//   - An opener pushes a span: its position, whether it is an isolate (closed
//     by PDI) or an embedding/override (closed by PDF), and whether it is
//     right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
//     LRI).
//   - Every other codepoint is recorded against the innermost open span only:
//     strong right-to-left (R or AL), strong left-to-right (L), or ASCII code
//     syntax. A nested span manages its own content.
//   - PDF closes the top span when it is an embedding; against an isolate on
//     top, or an empty stack, it is an orphan. PDI closes down to the innermost
//     isolate, implicitly terminating the embeddings above it, which are thereby
//     unbalanced; with no isolate open it is an orphan.
//   - A closed span is purposeful iff its direct content is exactly its own
//     direction and carries no code syntax; a left-to-right span additionally
//     needs right-to-left context (an enclosing right-to-left span, or a
//     paragraph whose first strong character is right-to-left).
//   - Reported: every orphan, every opener still open at the end, every
//     embedding a PDI terminated implicitly, and both ends of every closed span
//     that was not purposeful.
//
// The strong-direction predicates are the port's own IsStrongRtl / IsStrongLtr
// over the pinned bidi table.
public static partial class Security
{
    public static class BidiControlPurpose
    {
        /// <summary>RLE, RLO, RLI, or FSI (whose direction resolves from its
        /// content).</summary>
        public static bool OpensRtlKind(int cp) => cp is 0x202B or 0x202E or 0x2067 or 0x2068;

        /// <summary>LRE, LRO, LRI.</summary>
        public static bool OpensLtrKind(int cp) => cp is 0x202A or 0x202D or 0x2066;

        /// <summary>LRI, RLI, FSI.</summary>
        public static bool OpensIsolateKind(int cp) => cp is 0x2066 or 0x2067 or 0x2068;

        /// <summary>The ASCII codepoints a Trojan Source payload moves: quotes,
        /// brackets, comment markers, statement separators, operators. Prose
        /// punctuation, space and digits are not in the set.</summary>
        public static bool IsCodeSyntax(int cp) =>
            cp is 0x22 or 0x27 or 0x60 or 0x28 or 0x29 or 0x5B or 0x5D or 0x7B or 0x7D
                or 0x2F or 0x5C or 0x2A or 0x23 or 0x3B or 0x3C or 0x3E or 0x3D or 0x2B
                or 0x7C or 0x26 or 0x25 or 0x24 or 0x40 or 0x5E or 0x7E;

        /// <summary>UAX #9 P2/P3: the paragraph runs right-to-left iff its first
        /// strong character is right-to-left.</summary>
        public static bool ParagraphIsRtl(IReadOnlyList<int> input)
        {
            foreach (var cp in input)
            {
                if (Security.IsStrongRtl(cp)) return true;
                if (Security.IsStrongLtr(cp)) return false;
            }
            return false;
        }

        /// <summary>One open span: where it opened, how it closes, its direction
        /// in effect, and what has appeared directly inside it.</summary>
        private sealed class OpenSpan
        {
            public int Pos;
            public bool Isolate;
            public bool RtlKind;
            public bool SawRtl;
            public bool SawLtr;
            public bool SawSyntax;
        }

        // A closed span is purposeful iff its direct content is exactly its own
        // direction and carries no code syntax; a left-to-right span additionally
        // needs right-to-left context.
        private static bool SpanPurposeful(OpenSpan span, List<OpenSpan> enclosing, bool paragraphRtl)
        {
            if (span.RtlKind)
            {
                return span.SawRtl && !span.SawLtr && !span.SawSyntax;
            }
            var inRtlContext = paragraphRtl || enclosing.Exists(e => e.RtlKind);
            return inRtlContext && span.SawLtr && !span.SawRtl && !span.SawSyntax;
        }

        /// <summary>Positions of the purposeless bidi format controls in the
        /// input, in input order. Empty iff every control is balanced and manages
        /// right-to-left text.</summary>
        public static List<int> PurposelessControlPositions(IReadOnlyList<int> input)
        {
            var paragraphRtl = ParagraphIsRtl(input);
            // The stack's last element is the innermost open span.
            var stack = new List<OpenSpan>();
            var reported = new List<int>();

            for (var idx = 0; idx < input.Count; idx++)
            {
                var cp = input[idx];
                if (OpensRtlKind(cp) || OpensLtrKind(cp))
                {
                    stack.Add(new OpenSpan
                    {
                        Pos = idx,
                        Isolate = OpensIsolateKind(cp),
                        RtlKind = OpensRtlKind(cp),
                    });
                }
                else if (cp == 0x202C)
                {
                    // PDF closes the top embedding; an isolate on top or an
                    // empty stack makes it an orphan.
                    if (stack.Count == 0 || stack[stack.Count - 1].Isolate)
                    {
                        reported.Add(idx);
                    }
                    else
                    {
                        var top = stack[stack.Count - 1];
                        stack.RemoveAt(stack.Count - 1);
                        if (!SpanPurposeful(top, stack, paragraphRtl))
                        {
                            reported.Add(top.Pos);
                            reported.Add(idx);
                        }
                    }
                }
                else if (cp == 0x2069)
                {
                    // PDI closes down to the innermost isolate; the embeddings
                    // above it are terminated implicitly and so unbalanced. No
                    // isolate open: orphan.
                    var isoIndex = stack.FindLastIndex(s => s.Isolate);
                    if (isoIndex < 0)
                    {
                        reported.Add(idx);
                    }
                    else
                    {
                        for (var k = isoIndex + 1; k < stack.Count; k++)
                        {
                            reported.Add(stack[k].Pos);
                        }
                        var closed = stack[isoIndex];
                        stack.RemoveRange(isoIndex, stack.Count - isoIndex);
                        if (!SpanPurposeful(closed, stack, paragraphRtl))
                        {
                            reported.Add(closed.Pos);
                            reported.Add(idx);
                        }
                    }
                }
                else if (stack.Count > 0)
                {
                    var top = stack[stack.Count - 1];
                    top.SawRtl = top.SawRtl || Security.IsStrongRtl(cp);
                    top.SawLtr = top.SawLtr || Security.IsStrongLtr(cp);
                    top.SawSyntax = top.SawSyntax || IsCodeSyntax(cp);
                }
            }

            // Every opener still open at the end is unbalanced.
            foreach (var open in stack)
            {
                reported.Add(open.Pos);
            }

            return reported.Distinct().OrderBy(p => p).ToList();
        }

        /// <summary>True iff the input carries at least one purposeless bidi
        /// format control.</summary>
        public static bool HasPurposelessControl(IReadOnlyList<int> input) =>
            PurposelessControlPositions(input).Count > 0;

        /// <summary>Position and codepoint of the first purposeless control, or
        /// null when every control is purposeful.</summary>
        public static (int Pos, int Cp)? FirstPurposelessControl(IReadOnlyList<int> input)
        {
            var positions = PurposelessControlPositions(input);
            if (positions.Count == 0) return null;
            return (positions[0], input[positions[0]]);
        }
    }
}
