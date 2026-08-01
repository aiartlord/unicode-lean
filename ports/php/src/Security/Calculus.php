<?php

declare(strict_types=1);

namespace UnicodePhp\Security;

/// The detector modules. The order is the order in which the aggregator walks
/// them and the priority order callers can rely on when composing verdicts
/// across modules.
enum Family
{
    /// Strict UTF-8 decoder rejection before codepoint-level scanning.
    case MalformedUtf8;
    /// Strict UTF-16 decoder rejection before codepoint-level scanning.
    case MalformedUtf16;
    /// Strict UTF-32 decoder rejection before codepoint-level scanning.
    case MalformedUtf32;
    case TagBlockPayload;
    case VariationSelectorPayload;
    case ZeroWidthPayload;
    case SurrogateReassembly;
    case BidiControlBalance;
    case NoncharacterControl;
    case HomoglyphConfusable;
    case MixedScriptAdmissibility;
    case EmojiZwjIntegrity;
    case SkinToneVariationForgery;
    case SourceDisplayDivergence;
    case FilenameDisguise;
    case RtlInjection;
    case RendererDivergence;
    case NormalizationBomb;
    case StreamSafeViolation;
    case LocaleCaseInversion;
    case CaseExpansionMismatch;
    case WidthClassConfusion;
    case NfcIdempotenceWitness;
    case IdentifierFormDrift;
    case CovertDisplayCompound;
    case ConfusableBidiCompound;
    case AdmissibilityFormDrift;
    case Bip39Canonical;
    case HashInputStability;
    case AiWatermarkDetectability;
}

/// Ordered severity vocabulary. Strictly less-than:
/// `Informational < Low < Moderate < High < Critical`.
enum Severity: int
{
    case Informational = 0;
    case Low = 1;
    case Moderate = 2;
    case High = 3;
    case Critical = 4;
}

/// Five-tier adversary capability hierarchy.
///
///   - `A0` — passive observer
///   - `A1` — local injector (single-input attack)
///   - `A2` — pipeline injector (browser → API → DB → AI)
///   - `A3` — supply-chain injector (registers a package or identifier)
///   - `A4` — model-adaptive (tokenizer-query capable)
enum AdversaryTier: int
{
    case A0 = 0;
    case A1 = 1;
    case A2 = 2;
    case A3 = 3;
    case A4 = 4;
}

/// The verdict kind, independent of any family-specific sub-threat payload.
/// Family modules define their own classification types carrying sub-threat
/// data; this enum is the shape they all share.
enum ClassificationKind
{
    case Clear;
    case Hazard;
    case Compound;
    case Informational;
}

/// The default severity associated with each classification kind. Families can
/// override at the verdict level.
final class Calculus
{
    public static function defaultSeverity(ClassificationKind $kind): Severity
    {
        return match ($kind) {
            ClassificationKind::Clear => Severity::Informational,
            ClassificationKind::Hazard => Severity::Moderate,
            ClassificationKind::Compound => Severity::High,
            ClassificationKind::Informational => Severity::Informational,
        };
    }
}

/// A position within a codepoint sequence, optionally enriched with a line /
/// column when the input is source-code shaped.
final class HazardPosition
{
    public function __construct(
        public readonly int $cpOffset,
        public readonly ?int $line = null,
        public readonly ?int $column = null,
    ) {
    }
}

/// A flexible attribution dictionary — string keys to string values. Each
/// family defines its own attribution schema; this is the shared container.
final class KeyValueAttribution
{
    /// @var list<array{0:string,1:string}>
    private array $entries = [];

    /// Append a key-value pair.
    public function push(string $key, string $value): void
    {
        $this->entries[] = [$key, $value];
    }

    /// Look up the first value for `key`.
    public function get(string $key): ?string
    {
        foreach ($this->entries as $entry) {
            if ($entry[0] === $key) {
                return $entry[1];
            }
        }
        return null;
    }

    /// Borrow all entries.
    ///
    /// @return list<array{0:string,1:string}>
    public function entries(): array
    {
        return $this->entries;
    }
}
