<?php

declare(strict_types=1);

namespace UnicodePhp\Security\Identity;

// Identifier-shaped tokens of a running-text field.
//
// Direct port of Unicode/Security/Identity/IdentifierTokens.lean. A source
// line, a chat message or a display name is not one identifier, but the
// identifier-shaped words inside it are the surface a homoglyph attack targets
// (scоpe with a Cyrillic о in `let scоpe = 1;`). A token is a maximal run of
// XID_Continue codepoints; everything else (space, punctuation, operators,
// format controls) separates tokens. Each token carries its start position so a
// finding made on the token can be reported in input coordinates.
//
// XID_Continue is the port's own Ucd::isXidContinue over the bundled
// DerivedCoreProperties.txt.

final class IdentifierTokens
{
    /**
     * The maximal XID_Continue runs of the input, in input order, as
     * ['start' => int, 'cps' => list<int>] records.
     * @param list<int> $input
     * @return list<array{start:int,cps:list<int>}>
     */
    public static function tokens(array $input): array
    {
        $out = [];
        $start = 0;
        $current = null;
        foreach (array_values($input) as $idx => $cp) {
            if (Ucd::isXidContinue($cp)) {
                if ($current === null) {
                    $current = [];
                    $start = $idx;
                }
                $current[] = $cp;
            } elseif ($current !== null) {
                $out[] = ['start' => $start, 'cps' => $current];
                $current = null;
            }
        }
        if ($current !== null) {
            $out[] = ['start' => $start, 'cps' => $current];
        }
        return $out;
    }

    /**
     * Move token-local positions back into input coordinates.
     * @param list<int> $positions
     * @return list<int>
     */
    public static function shiftPositions(int $start, array $positions): array
    {
        $out = [];
        foreach ($positions as $pos) {
            $out[] = $pos + $start;
        }
        return $out;
    }
}
