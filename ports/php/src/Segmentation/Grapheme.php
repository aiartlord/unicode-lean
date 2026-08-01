<?php

declare(strict_types=1);

namespace UnicodePhp\Segmentation;

/// GB11 left-context state: mirrors the Lean `EPicState` / rust `EpicState`.
enum EpicState
{
    case None;
    case AfterEp;
    case AfterEpZwj;
}

/// GB9c left-context state: mirrors the Lean `InCBState` / rust `IncbState`.
enum IncbState
{
    case None;
    case Consonant;
    case Linker;
}

/// Running scan state, mirroring the Lean `State` / rust `State`.
final class GraphemeState
{
    public function __construct(
        public ?Gcb $prevClass,
        public EpicState $epicState,
        public IncbState $incbState,
        public int $riRun,
    ) {
    }

    public static function initial(): self
    {
        return new self(null, EpicState::None, IncbState::None, 0);
    }
}

/// UAX #29 default extended grapheme cluster segmentation.
///
/// A transcription of the Lean algorithm
/// `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`, mirroring the rust
/// ground-truth port `segmentation::grapheme`. The active Lean tree proves
/// `graphemeBreaks_eq_spec`, relating that algorithm to the declarative
/// UAX #29 GB1-GB999 specification. The state fields, rule order, and
/// transitions below mirror that reference.
final class Grapheme
{
    /// Grapheme_Cluster_Break class of `cp`, `Gcb::Other` when uncovered.
    ///
    /// The property tables are grouped by property value (as in the UCD
    /// source), not globally sorted by code point, so lookups scan linearly for
    /// the covering range — mirroring the verified Lean `find?`. Each class is a
    /// partition, so at most one range covers a code point and the first match
    /// is the only match.
    public static function lookupGcb(int $cp): Gcb
    {
        foreach (GraphemeTables::GCB_RANGES as $range) {
            if ($range[0] <= $cp && $cp <= $range[1]) {
                return $range[2];
            }
        }
        return Gcb::Other;
    }

    /// Indic_Conjunct_Break class of `cp`, `Incb::None` when uncovered.
    public static function lookupIncb(int $cp): Incb
    {
        foreach (GraphemeTables::INCB_RANGES as $range) {
            if ($range[0] <= $cp && $cp <= $range[1]) {
                return $range[2];
            }
        }
        return Incb::None;
    }

    /// Whether `cp` has the Extended_Pictographic property.
    public static function isExtPict(int $cp): bool
    {
        foreach (GraphemeTables::EXTPICT_RANGES as $range) {
            if ($range[0] <= $cp && $cp <= $range[1]) {
                return true;
            }
        }
        return false;
    }

    /// Whether a grapheme cluster break occurs immediately before `cp` given the
    /// running state. Implements UAX #29 GB1-GB999 in canonical order; first
    /// match wins, the trailing GB999 breaks every otherwise-unmatched pair.
    public static function shouldBreakBefore(int $cp, GraphemeState $s): bool
    {
        $bc = self::lookupGcb($cp);
        $incb = self::lookupIncb($cp);
        $isEp = self::isExtPict($cp);
        $pc = $s->prevClass;
        if ($pc === null) {
            return true; // GB1: sot ÷
        }
        if ($pc === Gcb::Cr && $bc === Gcb::Lf) {
            return false; // GB3: CR × LF
        }
        if ($pc === Gcb::Control || $pc === Gcb::Cr || $pc === Gcb::Lf) {
            return true; // GB4: (Control | CR | LF) ÷
        }
        if ($bc === Gcb::Control || $bc === Gcb::Cr || $bc === Gcb::Lf) {
            return true; // GB5: ÷ (Control | CR | LF)
        }
        if ($pc === Gcb::L
            && ($bc === Gcb::L || $bc === Gcb::V || $bc === Gcb::Lv || $bc === Gcb::Lvt)) {
            return false; // GB6: L × (L | V | LV | LVT)
        }
        if (($pc === Gcb::Lv || $pc === Gcb::V) && ($bc === Gcb::V || $bc === Gcb::T)) {
            return false; // GB7: (LV | V) × (V | T)
        }
        if (($pc === Gcb::Lvt || $pc === Gcb::T) && $bc === Gcb::T) {
            return false; // GB8: (LVT | T) × T
        }
        if ($bc === Gcb::Extend || $bc === Gcb::Zwj) {
            return false; // GB9: × (Extend | ZWJ)
        }
        if ($bc === Gcb::SpacingMark) {
            return false; // GB9a: × SpacingMark
        }
        if ($pc === Gcb::Prepend) {
            return false; // GB9b: Prepend ×
        }
        if ($s->incbState === IncbState::Linker && $incb === Incb::Consonant) {
            return false; // GB9c: Consonant (Extend|Linker)* Linker (Extend|Linker)* × Consonant
        }
        if ($s->epicState === EpicState::AfterEpZwj && $isEp) {
            return false; // GB11: ExtPict Extend* ZWJ × ExtPict
        }
        if ($bc === Gcb::RegionalIndicator && $s->riRun % 2 === 1) {
            return false; // GB12/GB13: odd-parity RI run extends
        }
        return true; // GB999: Any ÷ Any
    }

    /// Update the running state after consuming `cp`. Mirrors the Lean `advance`.
    public static function advance(int $cp, GraphemeState $s): GraphemeState
    {
        $bc = self::lookupGcb($cp);
        $incb = self::lookupIncb($cp);
        $isEp = self::isExtPict($cp);

        if ($isEp) {
            $epicState = EpicState::AfterEp;
        } elseif ($s->epicState === EpicState::AfterEp && $bc === Gcb::Extend) {
            $epicState = EpicState::AfterEp;
        } elseif ($s->epicState === EpicState::AfterEp && $bc === Gcb::Zwj) {
            $epicState = EpicState::AfterEpZwj;
        } else {
            $epicState = EpicState::None;
        }

        if ($incb === Incb::Consonant) {
            $incbState = IncbState::Consonant;
        } elseif ($s->incbState === IncbState::Consonant && $incb === Incb::Linker) {
            $incbState = IncbState::Linker;
        } elseif ($s->incbState === IncbState::Consonant && $incb === Incb::Extend) {
            $incbState = IncbState::Consonant;
        } elseif ($s->incbState === IncbState::Linker && $incb === Incb::Linker) {
            $incbState = IncbState::Linker;
        } elseif ($s->incbState === IncbState::Linker && $incb === Incb::Extend) {
            $incbState = IncbState::Linker;
        } else {
            $incbState = IncbState::None;
        }

        $riRun = $bc === Gcb::RegionalIndicator ? $s->riRun + 1 : 0;

        // rust stores `prev_class: Some(bc)`; here `prevClass` is simply the
        // non-null class of the consumed code point.
        return new GraphemeState($bc, $epicState, $incbState, $riRun);
    }

    /// Boundary mask of length `count($cps) + 1`. Entry `i` is `true` when a
    /// grapheme cluster break occurs immediately before position `i` — entry `0`
    /// is the GB1 start-of-text break, entry `count($cps)` the GB2 end-of-text
    /// break, both always `true`. Mirrors the Lean `graphemeBreaks`.
    ///
    /// @param list<int> $cps
    /// @return list<bool>
    public static function graphemeBreaks(array $cps): array
    {
        $bs = [];
        $s = GraphemeState::initial();
        foreach ($cps as $cp) {
            $bs[] = self::shouldBreakBefore($cp, $s);
            $s = self::advance($cp, $s);
        }
        $bs[] = true; // GB2: eot ÷
        return $bs;
    }

    /// Split `cps` into grapheme clusters (the code points between consecutive
    /// boundaries).
    ///
    /// @param list<int> $cps
    /// @return list<list<int>>
    public static function graphemeClusters(array $cps): array
    {
        $breaks = self::graphemeBreaks($cps);
        $out = [];
        $cur = [];
        foreach ($cps as $i => $cp) {
            if ($breaks[$i] && $cur !== []) {
                $out[] = $cur;
                $cur = [];
            }
            $cur[] = $cp;
        }
        if ($cur !== []) {
            $out[] = $cur;
        }
        return $out;
    }
}
