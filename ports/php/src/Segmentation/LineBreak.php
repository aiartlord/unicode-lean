<?php

declare(strict_types=1);

namespace UnicodePhp\Segmentation;

/// The left-hand context a boundary decision reads: the classes and code
/// points of the most recent characters LB9 did not absorb, plus the running
/// counters the rules keep. Mirrors the Lean `EffSnapshot`.
final class LineBreakState
{
    /**
     * @param ?Lb  $effPrev        Class of the most recent character that was
     *                             not CM or ZWJ.
     * @param int  $effPrevCp      Its code point; LB20a, LB21a and LB28a name
     *                             U+2010 and U+25CC.
     * @param ?Lb  $effPrevNoSp    Class of the most recent character that was
     *                             not CM, ZWJ or SP.
     * @param ?Lb  $effPrevPrev    Class of the second most recent character
     *                             LB9 did not absorb.
     * @param int  $effPrevPrevCp  Its code point.
     * @param bool $inPiQuoteWindow Whether an LB15a initial-punctuation quote
     *                             window is open.
     * @param int  $riRun          Length of the current regional-indicator
     *                             run, for LB30a.
     * @param bool $inNuChain      Whether an LB25 numeric chain is open.
     */
    public function __construct(
        public ?Lb $effPrev,
        public int $effPrevCp,
        public ?Lb $effPrevNoSp,
        public ?Lb $effPrevPrev,
        public int $effPrevPrevCp,
        public bool $inPiQuoteWindow,
        public int $riRun,
        public bool $inNuChain,
    ) {
    }

    public static function initial(): self
    {
        return new self(null, 0, null, null, 0, false, 0, false);
    }
}

/// UAX #14 default line breaking over code point sequences.
///
/// A transcription of the Lean algorithm
/// `Unicode.Segmentation.LineBreak.lineBreaks`, whose `lineBreaks_length`
/// theorem fixes the output shape: one break-opportunity flag per boundary
/// position. The rule order, rule bodies and snapshot fields below mirror
/// that reference — LB2 through LB31 in UAX #14 R7's canonical order, first
/// match winning, the trailing LB31 breaking every otherwise-unmatched pair.
///
/// Where a line may break is a property of a sequence rather than of a code
/// point, so the entry point returns a flag per boundary instead of a
/// predicate over code points.
///
/// Three mechanisms carry the context the rules read:
///
///   - LB1 is applied at lookup time by `resolvedClass`, which folds the
///     tailorable AI, CJ, SA, SG and XX into the algorithm's working
///     alphabet. SA needs General_Category to choose between CM and AL.
///   - LB9 — treat X CM* / X ZWJ* as X — is realised through
///     `LineBreakState`, whose fields hold the most recent class that was not
///     CM or ZWJ. LB10, treating a leftover CM or ZWJ as AL, is the fallback
///     taken when no such class exists.
///   - The rules naming a third character — LB15b, LB15c, the LB25 bracket
///     and the fourth LB28a sub-rule — read forward from the position being
///     decided.
///
/// Two departures from the Lean. Its positional reads are `lits[i]!` and
/// `cps[i]!`, panicking accessors; here every read is bounded by the length
/// of the array the caller already holds, so no access can leave the
/// sequence. And its `spSinceNoSp` snapshot field is written by its fold and
/// read by no rule, so this port omits it.
final class LineBreak
{
    /// U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0
    /// moved it from class HY to class HH.
    private const HYPHEN_U2010 = 0x2010;

    /// U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
    private const DOTTED_CIRCLE = 0x25CC;

    /// Line_Break class of `cp` before LB1. A code point no range covers is
    /// `Lb::Xx`, the default LineBreak.txt declares in its own
    /// `@missing: 0000..10FFFF; XX` header.
    public static function rawClass(int $cp): Lb
    {
        $low = 0;
        $high = count(LineBreakTables::LB_RANGES);
        while ($low < $high) {
            $mid = $low + intdiv($high - $low, 2);
            $range = LineBreakTables::LB_RANGES[$mid];
            if ($cp < $range[0]) {
                $high = $mid;
            } elseif ($cp > $range[1]) {
                $low = $mid + 1;
            } else {
                return $range[2];
            }
        }
        return Lb::Xx;
    }

    /// General_Category of `cp`, `Gc::Cn` when no range covers it — the
    /// default UnicodeData.txt declares for unassigned code points.
    public static function categoryOf(int $cp): Gc
    {
        $low = 0;
        $high = count(LineBreakTables::GC_RANGES);
        while ($low < $high) {
            $mid = $low + intdiv($high - $low, 2);
            $range = LineBreakTables::GC_RANGES[$mid];
            if ($cp < $range[0]) {
                $high = $mid;
            } elseif ($cp > $range[1]) {
                $low = $mid + 1;
            } else {
                return $range[2];
            }
        }
        return Gc::Cn;
    }

    /// East_Asian_Width of `cp`, `Eaw::N` when the file omits it.
    public static function widthOf(int $cp): Eaw
    {
        $low = 0;
        $high = count(LineBreakTables::EAW_RANGES);
        while ($low < $high) {
            $mid = $low + intdiv($high - $low, 2);
            $range = LineBreakTables::EAW_RANGES[$mid];
            if ($cp < $range[0]) {
                $high = $mid;
            } elseif ($cp > $range[1]) {
                $low = $mid + 1;
            } else {
                return $range[2];
            }
        }
        return Eaw::N;
    }

    /// Whether `cp` carries the Extended_Pictographic property, which LB30b
    /// reads.
    public static function isExtendedPictographic(int $cp): bool
    {
        $low = 0;
        $high = count(LineBreakTables::EXTPICT_RANGES);
        while ($low < $high) {
            $mid = $low + intdiv($high - $low, 2);
            $range = LineBreakTables::EXTPICT_RANGES[$mid];
            if ($cp < $range[0]) {
                $high = $mid;
            } elseif ($cp > $range[1]) {
                $low = $mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }

    /// Line_Break class `cp` carries once LB1 has tailored it.
    ///
    /// AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is
    /// a non-spacing or spacing combining mark and to AL otherwise. Every
    /// other class is already in the working alphabet.
    public static function resolvedClass(int $cp): Lb
    {
        $raw = self::rawClass($cp);
        return match ($raw) {
            Lb::Ai, Lb::Sg, Lb::Xx => Lb::Al,
            Lb::Cj => Lb::Ns,
            // LB1 reads only the two combining-mark categories here; an
            // enclosing mark is not among them.
            Lb::Sa => match (self::categoryOf($cp)) {
                Gc::Mn, Gc::Mc => Lb::Cm,
                default => Lb::Al,
            },
            default => $raw,
        };
    }

    /// Whether LB9 absorbs this class into the character before it.
    private static function isCmZwj(Lb $cls): bool
    {
        return $cls === Lb::Cm || $cls === Lb::Zwj;
    }

    /// Whether a preceding class blocks LB9's absorption, so a following CM
    /// or ZWJ stands on its own and LB10 reads it as AL.
    private static function blocksAbsorb(Lb $cls): bool
    {
        return $cls === Lb::Bk || $cls === Lb::Cr || $cls === Lb::Lf
            || $cls === Lb::Nl || $cls === Lb::Sp || $cls === Lb::Zw;
    }

    /// Whether the class is QU and the code point is initial punctuation, the
    /// refinement LB15a reads.
    private static function isPiQuote(int $cp, Lb $cls): bool
    {
        return $cls === Lb::Qu && self::categoryOf($cp) === Gc::Pi;
    }

    /// Whether the class is QU and the code point is final punctuation, the
    /// refinement LB15b reads.
    private static function isPfQuote(int $cp, Lb $cls): bool
    {
        return $cls === Lb::Qu && self::categoryOf($cp) === Gc::Pf;
    }

    /// Whether `cp` is East_Asian_Width F, W or H, the set LB25 and LB30 read.
    private static function isEastAsianFullWide(int $cp): bool
    {
        $width = self::widthOf($cp);
        return $width === Eaw::F || $width === Eaw::W || $width === Eaw::H;
    }

    /// Whether `cp` counts as East Asian for LB19a's tailoring, which treats
    /// Ambiguous as East Asian alongside Fullwidth, Wide and Halfwidth. Wider
    /// than `isEastAsianFullWide`.
    private static function isEastAsianOrAmbiguous(int $cp): bool
    {
        $width = self::widthOf($cp);
        return $width === Eaw::F || $width === Eaw::W || $width === Eaw::H
            || $width === Eaw::A;
    }

    /// Whether the effective class is present and among `$classes`.
    ///
    /// @param list<Lb> $classes
    private static function effIn(?Lb $effective, array $classes): bool
    {
        return $effective !== null && in_array($effective, $classes, true);
    }

    /// The class a CM or ZWJ takes from what it attaches to under LB9, or AL
    /// under LB10 when nothing absorbs it.
    private static function effectiveClass(Lb $cls, ?Lb $effPrev): Lb
    {
        if (!self::isCmZwj($cls)) {
            return $cls;
        }
        if ($effPrev === null) {
            return Lb::Al;
        }
        return self::blocksAbsorb($effPrev) ? Lb::Al : $cls;
    }

    /// One character folded into the context. A character LB9 absorbs leaves
    /// the context untouched, which is what makes the neighbours it records
    /// effective rather than literal. Mirrors the Lean `buildSnapshots` step.
    public static function advance(int $cp, Lb $cls, LineBreakState $s): LineBreakState
    {
        $effective = self::effectiveClass($cls, $s->effPrev);
        if (self::isCmZwj($effective)) {
            return $s;
        }

        // LB15a opens its window only where an initial-punctuation quote
        // stands outside a word; a space carries an open window forward.
        $leftContextOpens = $s->effPrev === null || self::effIn($s->effPrev, [
            Lb::Bk, Lb::Cr, Lb::Lf, Lb::Nl, Lb::Op, Lb::Qu, Lb::Gl, Lb::Sp,
            Lb::Zw,
        ]);
        $inPiQuoteWindow = false;
        if (self::isPiQuote($cp, $effective) && $leftContextOpens) {
            $inPiQuoteWindow = true;
        } elseif ($effective === Lb::Sp) {
            $inPiQuoteWindow = $s->inPiQuoteWindow;
        }

        $inNuChain = false;
        if ($effective === Lb::Nu) {
            $inNuChain = true;
        } elseif ($s->inNuChain) {
            $inNuChain = self::effIn($effective, [
                Lb::Sy, Lb::Is, Lb::Cl, Lb::Cp, Lb::Pr,
            ]);
        }

        return new LineBreakState(
            $effective,
            $cp,
            $effective === Lb::Sp ? $s->effPrevNoSp : $effective,
            $s->effPrev,
            $s->effPrevCp,
            $inPiQuoteWindow,
            $effective === Lb::Ri ? $s->riRun + 1 : 0,
            $inNuChain,
        );
    }

    /// Whether LB15b holds: the final quote is last, or what follows it
    /// cannot itself open a line.
    ///
    /// @param list<array{0: int, 1: Lb}> $pairs
    private static function finalQuoteCloses(array $pairs, int $ahead): bool
    {
        if ($ahead >= count($pairs)) {
            return true;
        }
        return self::effIn($pairs[$ahead][1], [
            Lb::Sp, Lb::Gl, Lb::Wj, Lb::Cl, Lb::Qu, Lb::Cp, Lb::Ex, Lb::Is,
            Lb::Sy, Lb::Bk, Lb::Cr, Lb::Lf, Lb::Nl, Lb::Zw,
        ]);
    }

    /// What the fourth LB28a sub-rule tests. It looks past any CM or ZWJ the
    /// cluster absorbs, so the character it reads is the first significant one
    /// ahead.
    ///
    /// @param list<array{0: int, 1: Lb}> $pairs
    private static function nextSignificantIsVf(array $pairs, int $ahead): bool
    {
        for ($at = $ahead; $at < count($pairs); $at++) {
            if (!self::isCmZwj($pairs[$at][1])) {
                return $pairs[$at][1] === Lb::Vf;
            }
        }
        return false;
    }

    /// Class at the head of the suffix starting at `$ahead`, or null where the
    /// suffix is empty.
    ///
    /// @param list<array{0: int, 1: Lb}> $pairs
    private static function headClass(array $pairs, int $ahead): ?Lb
    {
        return $ahead < count($pairs) ? $pairs[$ahead][1] : null;
    }

    /// Whether a line break opportunity falls immediately before the character
    /// at `$at`, given the character before it and the context accumulated
    /// from everything earlier. The characters from `$at` onward supply every
    /// lookahead the rules take.
    ///
    /// @param array{0: int, 1: Lb}       $prev
    /// @param list<array{0: int, 1: Lb}> $pairs
    private static function breaksBefore(
        array $prev,
        array $pairs,
        int $at,
        LineBreakState $s,
    ): bool {
        if ($at >= count($pairs)) {
            return true; // LB3
        }
        [$prevCp, $prevClass] = $prev;
        [$currentCp, $currentClass] = $pairs[$at];
        $ahead = $at + 1;

        $eff = self::effectiveClass($currentClass, $s->effPrev);
        $left = self::isCmZwj($prevClass) ? $s->effPrev : $prevClass;

        // LB4
        if ($prevClass === Lb::Bk) {
            return true;
        }
        // LB5
        if ($prevClass === Lb::Cr && $currentClass === Lb::Lf) {
            return false;
        }
        if (self::effIn($prevClass, [Lb::Cr, Lb::Lf, Lb::Nl])) {
            return true;
        }
        // LB6
        if (self::effIn($currentClass, [Lb::Bk, Lb::Cr, Lb::Lf, Lb::Nl])) {
            return false;
        }
        // LB7
        if ($currentClass === Lb::Sp || $currentClass === Lb::Zw) {
            return false;
        }
        // LB8
        if ($s->effPrevNoSp === Lb::Zw) {
            return true;
        }
        // LB8a
        if ($prevClass === Lb::Zwj) {
            return false;
        }
        // LB9
        if (self::isCmZwj($currentClass) && $s->effPrev !== null
            && !self::blocksAbsorb($s->effPrev)) {
            return false;
        }
        // LB11
        if ($eff === Lb::Wj || $left === Lb::Wj) {
            return false;
        }
        // LB12
        if ($left === Lb::Gl) {
            return false;
        }
        // LB12a
        if ($eff === Lb::Gl
            && !self::effIn($left, [Lb::Sp, Lb::Ba, Lb::Hy, Lb::Hh])) {
            return false;
        }
        // LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an
        // IS that opens a number and follows a space, as in "equals .35".
        if ($prevClass === Lb::Sp && $eff === Lb::Is
            && self::headClass($pairs, $ahead) === Lb::Nu) {
            return true;
        }
        // LB13
        if (self::effIn($eff, [Lb::Cl, Lb::Cp, Lb::Ex, Lb::Is, Lb::Sy])) {
            return false;
        }
        // LB14
        if ($s->effPrevNoSp === Lb::Op) {
            return false;
        }
        // LB15a
        if ($s->inPiQuoteWindow) {
            return false;
        }
        // LB15b
        if (self::isPfQuote($currentCp, $eff)
            && self::finalQuoteCloses($pairs, $ahead)) {
            return false;
        }
        // LB15d
        if ($eff === Lb::Is) {
            return false;
        }
        // LB16
        if ($eff === Lb::Ns
            && ($s->effPrevNoSp === Lb::Cl || $s->effPrevNoSp === Lb::Cp)) {
            return false;
        }
        // LB17
        if ($eff === Lb::B2 && $s->effPrevNoSp === Lb::B2) {
            return false;
        }
        // LB18
        if ($prevClass === Lb::Sp) {
            return true;
        }
        // LB19 and LB19a. A quote neither breaks before nor after, except on
        // the OUTER side of an initial or final punctuation quote standing in
        // contiguous East Asian content — there the default break applies, so
        // a line may break at the quote boundary. The inner side stays
        // unbroken, being the boundary inside the quote's own scope.
        if ($eff === Lb::Qu) {
            $nextEastAsian = $ahead < count($pairs)
                && self::isEastAsianOrAmbiguous($pairs[$ahead][0]);
            $openQuoteInEastAsian = self::isPiQuote($currentCp, $eff)
                && self::isEastAsianOrAmbiguous($prevCp)
                && self::isEastAsianOrAmbiguous($currentCp)
                && $nextEastAsian;
            if (!$openQuoteInEastAsian) {
                return false;
            }
        }
        if ($left === Lb::Qu) {
            $closeQuoteInEastAsian = false;
            if ($s->effPrev !== null) {
                $quoteCp = $s->effPrevCp;
                $closeQuoteInEastAsian = self::isPfQuote($quoteCp, Lb::Qu)
                    && $s->effPrevPrev !== null
                    && self::isEastAsianOrAmbiguous($s->effPrevPrevCp)
                    && self::isEastAsianOrAmbiguous($quoteCp)
                    && self::isEastAsianOrAmbiguous($currentCp);
            }
            if (!$closeQuoteInEastAsian) {
                return false;
            }
        }
        // LB20
        if ($eff === Lb::Cb || $left === Lb::Cb) {
            return true;
        }

        // LB20.1 and LB20a both require the hyphen's own left context to be
        // outside a word, the same start-of-segment set.
        $hyphenLeftContextOpens = $s->effPrevPrev === null
            || self::effIn($s->effPrevPrev, [
                Lb::Bk, Lb::Cr, Lb::Lf, Lb::Nl, Lb::Sp, Lb::Zw, Lb::Cb,
                Lb::Gl,
            ]);
        // LB20.1, UCD 17.0: an explicit hyphen joins a following letter only
        // where its own left context is outside a word. A mid-word HH falls
        // through to LB31.
        if ($left === Lb::Hh && self::effIn($eff, [Lb::Al, Lb::Hl])
            && $hyphenLeftContextOpens) {
            return false;
        }
        // LB20a, with UCD 17.0's right side broadened to HL beside AL.
        if (self::effIn($eff, [Lb::Al, Lb::Hl])) {
            $hyphenCarriesLeft = self::effIn($s->effPrev, [Lb::Hy, Lb::Hh])
                || ($s->effPrev !== null
                    && $s->effPrevCp === self::HYPHEN_U2010);
            if ($hyphenCarriesLeft && $hyphenLeftContextOpens) {
                return false;
            }
        }
        // LB21
        if (self::effIn($eff, [Lb::Ba, Lb::Hy, Lb::Hh, Lb::Ns])) {
            return false;
        }
        if ($left === Lb::Bb) {
            return false;
        }
        // LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what
        // comes next unless that is itself HL. A BA does not glue here.
        if ($s->effPrevPrev === Lb::Hl && $eff !== Lb::Hl) {
            $hyphenIsHyOr2010 = $s->effPrev === Lb::Hy
                || ($s->effPrev !== null
                    && $s->effPrevCp === self::HYPHEN_U2010);
            if ($hyphenIsHyOr2010) {
                return false;
            }
        }
        // LB21b
        if ($eff === Lb::Hl && $left === Lb::Sy) {
            return false;
        }
        // LB22
        if ($eff === Lb::In) {
            return false;
        }
        // LB23
        if ($eff === Lb::Nu && self::effIn($left, [Lb::Al, Lb::Hl])) {
            return false;
        }
        if (self::effIn($eff, [Lb::Al, Lb::Hl]) && $left === Lb::Nu) {
            return false;
        }
        // LB23a
        if (self::effIn($eff, [Lb::Id, Lb::Eb, Lb::Em]) && $left === Lb::Pr) {
            return false;
        }
        if ($eff === Lb::Po && self::effIn($left, [Lb::Id, Lb::Eb, Lb::Em])) {
            return false;
        }
        // LB24
        if (self::effIn($eff, [Lb::Al, Lb::Hl])
            && self::effIn($left, [Lb::Pr, Lb::Po])) {
            return false;
        }
        if (self::effIn($eff, [Lb::Pr, Lb::Po])
            && self::effIn($left, [Lb::Al, Lb::Hl])) {
            return false;
        }
        // LB25, closing an open numeric chain with a CL or CP suffix and a
        // following PO or PR.
        if ($s->inNuChain
            && self::effIn($eff, [Lb::Cl, Lb::Cp, Lb::Po, Lb::Pr])) {
            return false;
        }
        // LB25, opening a chain
        if ($eff === Lb::Nu
            && self::effIn($left, [Lb::Pr, Lb::Po, Lb::Hy, Lb::Op, Lb::Is])) {
            return false;
        }
        // LB25, chain body
        if ($eff === Lb::Nu && $left === Lb::Nu) {
            return false;
        }
        // LB25, extending an open chain across a SY
        if ($eff === Lb::Nu && $left === Lb::Sy && $s->inNuChain) {
            return false;
        }
        // LB25, bracketed prefix: a PR joins an OP only when the OP itself
        // opens a number, and neither is East Asian Fullwidth, Wide or
        // Halfwidth.
        if ($eff === Lb::Op && $left === Lb::Pr
            && !self::isEastAsianFullWide($currentCp)
            && $s->effPrev !== null
            && !self::isEastAsianFullWide($s->effPrevCp)
            && self::headClass($pairs, $ahead) === Lb::Nu) {
            return false;
        }
        // LB26
        if ($left === Lb::Jl
            && self::effIn($eff, [Lb::Jl, Lb::Jv, Lb::H2, Lb::H3])) {
            return false;
        }
        if (self::effIn($left, [Lb::Jv, Lb::H2])
            && self::effIn($eff, [Lb::Jv, Lb::Jt])) {
            return false;
        }
        if (self::effIn($left, [Lb::Jt, Lb::H3]) && $eff === Lb::Jt) {
            return false;
        }
        // LB27
        if (self::effIn($left, [Lb::Jl, Lb::Jv, Lb::Jt, Lb::H2, Lb::H3])
            && self::effIn($eff, [Lb::In, Lb::Po])) {
            return false;
        }
        if ($left === Lb::Pr
            && self::effIn($eff, [Lb::Jl, Lb::Jv, Lb::Jt, Lb::H2, Lb::H3])) {
            return false;
        }
        // LB28
        if (self::effIn($eff, [Lb::Al, Lb::Hl])
            && self::effIn($left, [Lb::Al, Lb::Hl])) {
            return false;
        }

        // LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class
        // AL and stands in for a cluster base throughout.
        $leftIsAksaraBase = self::effIn($left, [Lb::Ak, Lb::As])
            || ($s->effPrevCp === self::DOTTED_CIRCLE
                && $s->effPrev === Lb::Al);
        if ($left === Lb::Ap
            && (self::effIn($eff, [Lb::Ak, Lb::As])
                || $currentCp === self::DOTTED_CIRCLE)) {
            return false;
        }
        if ($leftIsAksaraBase && self::effIn($eff, [Lb::Vf, Lb::Vi])) {
            return false;
        }
        if ($s->effPrev === Lb::Vi
            && (self::effIn($s->effPrevPrev, [Lb::Ak, Lb::As])
                || ($s->effPrevPrev !== null
                    && $s->effPrevPrevCp === self::DOTTED_CIRCLE))
            && ($eff === Lb::Ak || $currentCp === self::DOTTED_CIRCLE)) {
            return false;
        }
        if ($leftIsAksaraBase
            && (self::effIn($eff, [Lb::Ak, Lb::As])
                || $currentCp === self::DOTTED_CIRCLE)
            && self::nextSignificantIsVf($pairs, $ahead)) {
            return false;
        }
        // LB29
        if (self::effIn($eff, [Lb::Al, Lb::Hl]) && $left === Lb::Is) {
            return false;
        }
        // LB30, where the bracket must not be East Asian Fullwidth, Wide or
        // Halfwidth.
        if ($eff === Lb::Op && self::effIn($left, [Lb::Al, Lb::Hl, Lb::Nu])
            && !self::isEastAsianFullWide($currentCp)) {
            return false;
        }
        if (self::effIn($eff, [Lb::Al, Lb::Hl, Lb::Nu]) && $left === Lb::Cp
            && !self::isEastAsianFullWide($prevCp)) {
            return false;
        }
        // LB30a
        if ($eff === Lb::Ri && $s->riRun % 2 === 1) {
            return false;
        }
        // LB30b
        if ($eff === Lb::Em && $left === Lb::Eb) {
            return false;
        }
        if ($eff === Lb::Em && $s->effPrev !== null) {
            $previous = $s->effPrevCp;
            if (self::isExtendedPictographic($previous)
                && self::categoryOf($previous) === Gc::Cn) {
                return false;
            }
        }
        // LB31
        return true;
    }

    /// Boundary mask of length `count($cps) + 1` — the shape the Lean
    /// `lineBreaks_length` theorem fixes. Entry `0` is `false`, LB2
    /// forbidding a break at the start of text, and the last entry is `true`
    /// per LB3, which requires one at the end.
    ///
    /// @param list<int> $cps
    /// @return list<bool>
    public static function lineBreaks(array $cps): array
    {
        $pairs = [];
        foreach ($cps as $cp) {
            $pairs[] = [$cp, self::resolvedClass($cp)];
        }
        $breaks = [];
        $s = LineBreakState::initial();
        $count = count($pairs);
        for ($i = 0; $i < $count; $i++) {
            $breaks[] = $i !== 0
                && self::breaksBefore($pairs[$i - 1], $pairs, $i, $s);
            $s = self::advance($pairs[$i][0], $pairs[$i][1], $s);
        }
        $breaks[] = true; // LB3
        return $breaks;
    }

    /// The code point sequence split at every break opportunity — the runs a
    /// renderer may place on separate lines.
    ///
    /// @param list<int> $cps
    /// @return list<list<int>>
    public static function lineRuns(array $cps): array
    {
        $breaks = self::lineBreaks($cps);
        $runs = [];
        $current = [];
        foreach ($cps as $i => $cp) {
            $current[] = $cp;
            if ($breaks[$i + 1]) {
                $runs[] = $current;
                $current = [];
            }
        }
        if ($current !== []) {
            $runs[] = $current;
        }
        return $runs;
    }
}
