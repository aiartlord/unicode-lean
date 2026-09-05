<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Display;

use UnicodePhp\Security\Identity\Ucd;

// Which bidi format controls serve a purpose, and which do not.
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
//
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
// The strong-direction predicates are the port's own Ucd::isStrongRtl /
// Ucd::isStrongLtr over the pinned bidi table.

final class BidiControlPurpose
{
    /**
     * The ASCII codepoints a Trojan Source payload moves: quotes, brackets,
     * comment markers, statement separators, operators. Prose punctuation, space
     * and digits are not in the set.
     */
    private const CODE_SYNTAX = [
        0x22, 0x27, 0x60, 0x28, 0x29, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x5C, 0x2A,
        0x23, 0x3B, 0x3C, 0x3E, 0x3D, 0x2B, 0x7C, 0x26, 0x25, 0x24, 0x40, 0x5E,
        0x7E,
    ];

    /** RLE, RLO, RLI, or FSI (whose direction resolves from its content). */
    public static function opensRtlKind(int $cp): bool
    {
        return $cp === 0x202B || $cp === 0x202E || $cp === 0x2067 || $cp === 0x2068;
    }

    /** LRE, LRO, LRI. */
    public static function opensLtrKind(int $cp): bool
    {
        return $cp === 0x202A || $cp === 0x202D || $cp === 0x2066;
    }

    /** LRI, RLI, FSI. */
    public static function opensIsolateKind(int $cp): bool
    {
        return $cp === 0x2066 || $cp === 0x2067 || $cp === 0x2068;
    }

    public static function isCodeSyntax(int $cp): bool
    {
        return in_array($cp, self::CODE_SYNTAX, true);
    }

    /**
     * UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
     * character is right-to-left.
     * @param list<int> $input
     */
    public static function paragraphIsRtl(array $input): bool
    {
        foreach ($input as $cp) {
            if (Ucd::isStrongRtl($cp)) {
                return true;
            }
            if (Ucd::isStrongLtr($cp)) {
                return false;
            }
        }
        return false;
    }

    /**
     * A closed span is purposeful iff its direct content is exactly its own
     * direction and carries no code syntax; a left-to-right span additionally
     * needs right-to-left context. Spans are arrays with keys pos, isolate,
     * rtlKind, sawRtl, sawLtr, sawSyntax.
     * @param array{pos:int,isolate:bool,rtlKind:bool,sawRtl:bool,sawLtr:bool,sawSyntax:bool} $span
     * @param list<array{pos:int,isolate:bool,rtlKind:bool,sawRtl:bool,sawLtr:bool,sawSyntax:bool}> $enclosing
     */
    private static function spanPurposeful(array $span, array $enclosing, bool $paragraphRtl): bool
    {
        if ($span['rtlKind']) {
            return $span['sawRtl'] && !$span['sawLtr'] && !$span['sawSyntax'];
        }
        $inRtlContext = $paragraphRtl;
        foreach ($enclosing as $e) {
            if ($e['rtlKind']) {
                $inRtlContext = true;
            }
        }
        return $inRtlContext && $span['sawLtr'] && !$span['sawRtl'] && !$span['sawSyntax'];
    }

    /**
     * Positions of the purposeless bidi format controls in the input, in input
     * order. Empty iff every control is balanced and manages right-to-left text.
     * @param list<int> $input
     * @return list<int>
     */
    public static function purposelessControlPositions(array $input): array
    {
        $input = array_values($input);
        $paragraphRtl = self::paragraphIsRtl($input);
        // The stack's last element is the innermost open span.
        $stack = [];
        $reported = [];

        foreach ($input as $idx => $cp) {
            if (self::opensRtlKind($cp) || self::opensLtrKind($cp)) {
                $stack[] = [
                    'pos' => $idx,
                    'isolate' => self::opensIsolateKind($cp),
                    'rtlKind' => self::opensRtlKind($cp),
                    'sawRtl' => false,
                    'sawLtr' => false,
                    'sawSyntax' => false,
                ];
            } elseif ($cp === 0x202C) {
                // PDF closes the top embedding; an isolate on top or an empty
                // stack makes it an orphan.
                $top = $stack === [] ? null : $stack[count($stack) - 1];
                if ($top === null || $top['isolate']) {
                    $reported[] = $idx;
                } else {
                    array_pop($stack);
                    if (!self::spanPurposeful($top, $stack, $paragraphRtl)) {
                        $reported[] = $top['pos'];
                        $reported[] = $idx;
                    }
                }
            } elseif ($cp === 0x2069) {
                // PDI closes down to the innermost isolate; the embeddings above
                // it are terminated implicitly and so unbalanced. No isolate
                // open: orphan.
                $isoIndex = null;
                for ($k = count($stack) - 1; $k >= 0; $k--) {
                    if ($stack[$k]['isolate']) {
                        $isoIndex = $k;
                        break;
                    }
                }
                if ($isoIndex === null) {
                    $reported[] = $idx;
                } else {
                    for ($k = $isoIndex + 1; $k < count($stack); $k++) {
                        $reported[] = $stack[$k]['pos'];
                    }
                    $closed = $stack[$isoIndex];
                    $stack = array_slice($stack, 0, $isoIndex);
                    if (!self::spanPurposeful($closed, $stack, $paragraphRtl)) {
                        $reported[] = $closed['pos'];
                        $reported[] = $idx;
                    }
                }
            } elseif ($stack !== []) {
                $topIndex = count($stack) - 1;
                $stack[$topIndex]['sawRtl'] = $stack[$topIndex]['sawRtl'] || Ucd::isStrongRtl($cp);
                $stack[$topIndex]['sawLtr'] = $stack[$topIndex]['sawLtr'] || Ucd::isStrongLtr($cp);
                $stack[$topIndex]['sawSyntax'] = $stack[$topIndex]['sawSyntax'] || self::isCodeSyntax($cp);
            }
        }

        // Every opener still open at the end is unbalanced.
        foreach ($stack as $open) {
            $reported[] = $open['pos'];
        }

        $reported = array_values(array_unique($reported));
        sort($reported);
        return $reported;
    }

    /**
     * True iff the input carries at least one purposeless bidi format control.
     * @param list<int> $input
     */
    public static function hasPurposelessControl(array $input): bool
    {
        return self::purposelessControlPositions($input) !== [];
    }

    /**
     * Position and codepoint of the first purposeless control, or null when
     * every control is purposeful.
     * @param list<int> $input
     * @return array{0:int,1:int}|null
     */
    public static function firstPurposelessControl(array $input): ?array
    {
        $input = array_values($input);
        $positions = self::purposelessControlPositions($input);
        if ($positions === []) {
            return null;
        }
        return [$positions[0], $input[$positions[0]]];
    }
}
