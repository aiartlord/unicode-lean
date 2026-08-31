<?php

declare(strict_types=1);

namespace UnicodePhp\Security;

use UnicodePhp\Noncharacters;
use UnicodePhp\Utf8;
use UnicodePhp\Security\Boundary\AdmissibilityFormDrift;
use UnicodePhp\Security\Boundary\ConfusableBidiCompound;
use UnicodePhp\Security\Boundary\CovertDisplayCompound;
use UnicodePhp\Security\Boundary\IdentifierFormDrift;
use UnicodePhp\Security\Covert\BidiControlBalance;
use UnicodePhp\Security\Covert\SurrogateReassembly;
use UnicodePhp\Security\Covert\TagBlockPayload;
use UnicodePhp\Security\Covert\VariationSelectorPayload;
use UnicodePhp\Security\Covert\ZeroWidthPayload;
use UnicodePhp\Security\Crypto\AiWatermarkDetectability;
use UnicodePhp\Security\Crypto\Bip39Canonical;
use UnicodePhp\Security\Crypto\HashInputStability;
use UnicodePhp\Security\Display\FilenameDisguise;
use UnicodePhp\Security\Display\RendererDivergence;
use UnicodePhp\Security\Display\RtlInjection;
use UnicodePhp\Security\Display\SourceDisplayDivergence;
use UnicodePhp\Security\Form\CaseExpansionMismatch;
use UnicodePhp\Security\Form\LocaleCaseInversion;
use UnicodePhp\Security\Form\NfcIdempotenceWitness;
use UnicodePhp\Security\Form\NormalizationBomb;
use UnicodePhp\Security\Form\StreamSafeViolation;
use UnicodePhp\Security\Form\WidthClassConfusion;
use UnicodePhp\Security\Identity\EmojiZwjIntegrity;
use UnicodePhp\Security\Identity\HomoglyphConfusable;
use UnicodePhp\Security\Identity\SkinToneVariationForgery;

enum Action: string
{
    case Allow = 'allow';
    case Reject = 'reject';
    case Quarantine = 'quarantine';
    case Rewrite = 'rewrite';
    case Observe = 'observe';
}

enum Mode: string
{
    case Observe = 'observe';
    case Warn = 'warn';
    case Enforce = 'enforce';
    case Strict = 'strict';
}

enum Profile: string
{
    case GatewayHeader = 'gateway-header';
    case DomainName = 'domain-name';
    case DnsLabel = 'dns-label';
    case Url = 'url';
    case Username = 'username';
    case DisplayName = 'display-name';
    case ChatMessage = 'chat-message';
    case SourceCode = 'source-code';
    case OpaqueSecret = 'opaque-secret';
    case BinaryBlob = 'binary-blob';
}

enum PolicyLevel
{
    case Restrictive;
    case Moderate;
    case Minimal;
}

enum CryptoContext
{
    case NonCrypto;
    case Bip39Mnemonic;
    case HashInput;
    case AiAttribution;
}

final class ProfilePolicy
{
    public function __construct(
        public readonly PolicyLevel $level,
        public readonly CryptoContext $cryptoContext,
        public readonly bool $quarantine,
    ) {
    }
}

final class Finding
{
    /** @param list<int> $positions */
    public function __construct(
        public readonly string $code,
        public readonly Family $family,
        public readonly Severity $severity,
        public readonly array $positions,
        public readonly ?string $subThreat,
        public readonly string $detail,
    ) {
    }
}

final class Verdict
{
    /** @param list<int> $input @param list<Finding> $findings @param list<int>|null $normalized */
    public function __construct(
        public readonly array $input,
        public readonly Profile $profile,
        public readonly Mode $mode,
        public readonly Action $action,
        public readonly array $findings,
        public readonly ?array $normalized,
    ) {
    }
}

final class Policy
{
    /** @return list<Family> */
    public static function cryptoFamilies(CryptoContext $context): array
    {
        return match ($context) {
            CryptoContext::Bip39Mnemonic => [Family::Bip39Canonical],
            CryptoContext::HashInput => [Family::HashInputStability],
            CryptoContext::AiAttribution => [Family::AiWatermarkDetectability],
            CryptoContext::NonCrypto => [],
        };
    }

    /** @return list<Family> */
    public static function rejectionSet(PolicyLevel $level): array
    {
        $restrictive = [
            Family::MalformedUtf8, Family::MalformedUtf16, Family::MalformedUtf32,
            Family::TagBlockPayload, Family::VariationSelectorPayload, Family::ZeroWidthPayload,
            Family::SurrogateReassembly, Family::BidiControlBalance, Family::NoncharacterControl,
            Family::HomoglyphConfusable, Family::MixedScriptAdmissibility, Family::EmojiZwjIntegrity,
            Family::SkinToneVariationForgery, Family::SourceDisplayDivergence, Family::FilenameDisguise,
            Family::RtlInjection, Family::RendererDivergence, Family::NormalizationBomb,
            Family::StreamSafeViolation, Family::LocaleCaseInversion, Family::CaseExpansionMismatch,
            Family::WidthClassConfusion, Family::NfcIdempotenceWitness, Family::IdentifierFormDrift,
            Family::CovertDisplayCompound, Family::ConfusableBidiCompound, Family::AdmissibilityFormDrift,
        ];
        $moderate = [
            Family::MalformedUtf8, Family::MalformedUtf16, Family::MalformedUtf32,
            Family::TagBlockPayload, Family::VariationSelectorPayload, Family::ZeroWidthPayload,
            Family::SurrogateReassembly, Family::BidiControlBalance, Family::NoncharacterControl,
            Family::HomoglyphConfusable, Family::MixedScriptAdmissibility, Family::SkinToneVariationForgery,
            Family::SourceDisplayDivergence, Family::FilenameDisguise, Family::StreamSafeViolation,
            Family::LocaleCaseInversion, Family::CaseExpansionMismatch, Family::WidthClassConfusion,
            Family::NfcIdempotenceWitness, Family::IdentifierFormDrift, Family::CovertDisplayCompound,
            Family::ConfusableBidiCompound, Family::AdmissibilityFormDrift,
        ];
        $minimal = [
            Family::MalformedUtf8, Family::MalformedUtf16, Family::MalformedUtf32,
            Family::SurrogateReassembly, Family::BidiControlBalance, Family::NoncharacterControl,
            Family::StreamSafeViolation,
        ];
        return match ($level) {
            PolicyLevel::Restrictive => $restrictive,
            PolicyLevel::Moderate => $moderate,
            PolicyLevel::Minimal => $minimal,
        };
    }

    /**
     * True iff the profile names a field holding one identifier, not running
     * text. A username, a registrable domain and a DNS label are single
     * identifiers, so a codepoint outside the General Security Profile is a
     * hazard in them. The remaining profiles carry prose, source, URLs or
     * opaque bytes, where a space and a punctuation mark are ordinary content.
     * Mirrors profileIsIdentifierField in Unicode/Security/Policy.lean.
     */
    public static function profileIsIdentifierField(Profile $profile): bool
    {
        return $profile === Profile::DomainName
            || $profile === Profile::DnsLabel
            || $profile === Profile::Username;
    }

    public static function policyOfProfile(Profile $profile): ProfilePolicy
    {
        return match ($profile) {
            Profile::GatewayHeader, Profile::DomainName, Profile::DnsLabel
                => new ProfilePolicy(PolicyLevel::Restrictive, CryptoContext::NonCrypto, false),
            // Source files legitimately carry right-to-left string
            // literals, comments written in Hebrew or Arabic, and emoji.
            // Restrictive admits RtlInjection, whose contract treats its
            // input as a declared-LTR field, so under it an ordinary Hebrew
            // comment is rejected. Moderate retains every detector that
            // catches the Trojan Source class while dropping the
            // field-direction assumption a source file does not satisfy.
            Profile::Url, Profile::SourceCode
                => new ProfilePolicy(PolicyLevel::Moderate, CryptoContext::NonCrypto, false),
            Profile::Username => new ProfilePolicy(PolicyLevel::Moderate, CryptoContext::NonCrypto, true),
            Profile::DisplayName, Profile::ChatMessage => new ProfilePolicy(PolicyLevel::Minimal, CryptoContext::NonCrypto, true),
            Profile::OpaqueSecret => new ProfilePolicy(PolicyLevel::Minimal, CryptoContext::HashInput, false),
            Profile::BinaryBlob => new ProfilePolicy(PolicyLevel::Minimal, CryptoContext::NonCrypto, false),
        };
    }

    public static function familySlug(Family $family): string
    {
        return match ($family) {
            Family::MalformedUtf8 => 'malformed-utf8',
            Family::MalformedUtf16 => 'malformed-utf16',
            Family::MalformedUtf32 => 'malformed-utf32',
            Family::TagBlockPayload => 'tag-block-payload',
            Family::VariationSelectorPayload => 'variation-selector-payload',
            Family::ZeroWidthPayload => 'zero-width-payload',
            Family::SurrogateReassembly => 'surrogate-reassembly',
            Family::BidiControlBalance => 'bidi-control-balance',
            Family::NoncharacterControl => 'noncharacter-control',
            Family::HomoglyphConfusable => 'homoglyph-confusable',
            Family::MixedScriptAdmissibility => 'mixed-script-admissibility',
            Family::EmojiZwjIntegrity => 'emoji-zwj-integrity',
            Family::SkinToneVariationForgery => 'skin-tone-variation-forgery',
            Family::SourceDisplayDivergence => 'source-display-divergence',
            Family::FilenameDisguise => 'filename-disguise',
            Family::RtlInjection => 'rtl-injection',
            Family::RendererDivergence => 'renderer-divergence',
            Family::NormalizationBomb => 'normalization-bomb',
            Family::StreamSafeViolation => 'stream-safe-violation',
            Family::LocaleCaseInversion => 'locale-case-inversion',
            Family::CaseExpansionMismatch => 'case-expansion-mismatch',
            Family::WidthClassConfusion => 'width-class-confusion',
            Family::NfcIdempotenceWitness => 'nfc-idempotence-witness',
            Family::IdentifierFormDrift => 'identifier-form-drift',
            Family::CovertDisplayCompound => 'covert-display-compound',
            Family::ConfusableBidiCompound => 'confusable-bidi-compound',
            Family::AdmissibilityFormDrift => 'admissibility-form-drift',
            Family::Bip39Canonical => 'bip39-canonical',
            Family::HashInputStability => 'hash-input-stability',
            Family::AiWatermarkDetectability => 'ai-watermark-detectability',
        };
    }

    public static function familyLayerCode(Family $family): string
    {
        return match ($family) {
            Family::MalformedUtf8, Family::MalformedUtf16, Family::MalformedUtf32,
            Family::TagBlockPayload, Family::VariationSelectorPayload, Family::ZeroWidthPayload,
            Family::SurrogateReassembly, Family::BidiControlBalance, Family::NoncharacterControl => 'C',
            Family::HomoglyphConfusable, Family::MixedScriptAdmissibility,
            Family::EmojiZwjIntegrity, Family::SkinToneVariationForgery => 'I',
            Family::SourceDisplayDivergence, Family::FilenameDisguise,
            Family::RtlInjection, Family::RendererDivergence => 'D',
            Family::NormalizationBomb, Family::StreamSafeViolation, Family::LocaleCaseInversion,
            Family::CaseExpansionMismatch, Family::WidthClassConfusion, Family::NfcIdempotenceWitness => 'F',
            Family::IdentifierFormDrift, Family::CovertDisplayCompound,
            Family::ConfusableBidiCompound, Family::AdmissibilityFormDrift => 'X',
            default => 'K',
        };
    }

    public static function reasonCode(Family $family, ?string $sub = null): string
    {
        return 'unicode.security.' . self::familyLayerCode($family) . '.' . self::familySlug($family) . '.' . ($sub ?? 'hazard');
    }

    public static function familyBlocks(Profile $profile, Family $family): bool
    {
        foreach (self::rejectionSet(self::policyOfProfile($profile)->level) as $blocked) {
            if ($blocked === $family) {
                return true;
            }
        }
        return false;
    }

    /** @param list<Finding> $findings */
    public static function selectAction(Profile $profile, Mode $mode, array $findings): Action
    {
        $hasFindings = $findings !== [];
        $hasBlocking = false;
        foreach ($findings as $finding) {
            if (self::familyBlocks($profile, $finding->family)) {
                $hasBlocking = true;
                break;
            }
        }
        return match ($mode) {
            Mode::Observe, Mode::Warn => $hasFindings ? Action::Observe : Action::Allow,
            Mode::Enforce => !$hasBlocking ? Action::Allow : (self::policyOfProfile($profile)->quarantine ? Action::Quarantine : Action::Reject),
            Mode::Strict => $hasFindings ? Action::Reject : Action::Allow,
        };
    }

    private static function subTag(mixed $sub): ?string
    {
        if ($sub === null) {
            return null;
        }
        if (is_string($sub)) {
            return $sub;
        }
        if (is_object($sub) && property_exists($sub, 'tag')) {
            return $sub->tag;
        }
        if (is_object($sub) && method_exists($sub, 'tag')) {
            return $sub->tag();
        }
        return (string) $sub;
    }

    /** @param list<Finding> $findings @param list<int> $positions */
    private static function pushFinding(array &$findings, Family $family, ClassificationKind $kind, mixed $sub, array $positions): void
    {
        if ($kind === ClassificationKind::Clear) {
            return;
        }
        $tag = self::subTag($sub);
        $severity = match ($kind) {
            ClassificationKind::Compound => Severity::High,
            ClassificationKind::Hazard => Severity::Moderate,
            default => Severity::Informational,
        };
        $findings[] = new Finding(self::reasonCode($family, $tag), $family, $severity, $positions, $tag, self::familySlug($family));
    }

    /** @param list<Finding> $findings @param list<int> $positions */
    private static function pushPositionalHazard(array &$findings, Family $family, string $sub, array $positions): void
    {
        if ($positions !== []) {
            self::pushFinding($findings, $family, ClassificationKind::Hazard, $sub, $positions);
        }
    }

    /** @param list<int> $input @return list<int> */
    private static function positionsWhere(array $input, callable $pred): array
    {
        $out = [];
        foreach ($input as $i => $cp) {
            if ($pred($cp)) {
                $out[] = $i;
            }
        }
        return $out;
    }

    private static function c0Control(int $cp): bool
    {
        return ($cp >= 0 && $cp <= 0x1F && $cp !== 0x09 && $cp !== 0x0A && $cp !== 0x0D) || $cp === 0x7F;
    }

    private static function c1Control(int $cp): bool
    {
        return $cp >= 0x80 && $cp <= 0x9F;
    }

    /** @param list<int> $input */
    public static function scan(Profile $profile, Mode $mode, array $input): Verdict
    {
        $findings = [];

        $tag = TagBlockPayload::detect($input);
        self::pushFinding($findings, Family::TagBlockPayload, $tag->kind, $tag->sub, $tag->tagPositions);

        $vs = VariationSelectorPayload::detect($input);
        self::pushFinding($findings, Family::VariationSelectorPayload, $vs->kind, $vs->sub, $vs->vsPositions);

        $zw = ZeroWidthPayload::detect($input);
        self::pushFinding($findings, Family::ZeroWidthPayload, $zw->kind, $zw->sub, $zw->zeroWidthPositions);

        if (SurrogateReassembly::looksLikeByteStream($input)) {
            $sr = SurrogateReassembly::detect($input);
            if ($sr->sub !== null) {
                self::pushFinding($findings, Family::SurrogateReassembly, ClassificationKind::Hazard, $sr->sub, $sr->positions);
            }
        }

        $bidi = BidiControlBalance::detect($input);
        self::pushFinding($findings, Family::BidiControlBalance, $bidi->kind, $bidi->sub, $bidi->bidiPositions);

        self::pushPositionalHazard($findings, Family::NoncharacterControl, 'Noncharacter', self::positionsWhere($input, [Noncharacters::class, 'isNoncharacter']));
        self::pushPositionalHazard($findings, Family::NoncharacterControl, 'C0Control', self::positionsWhere($input, [self::class, 'c0Control']));
        self::pushPositionalHazard($findings, Family::NoncharacterControl, 'C1Control', self::positionsWhere($input, [self::class, 'c1Control']));

        $h = HomoglyphConfusable::detect($input);
        // Every rung of the homoglyph ladder is reported, CrossScriptMix
        // included. Unicode/Security/Policy.lean maps every non-clear family
        // result to a finding without filtering, so suppressing this rung would
        // report fewer findings than the proven spec for a cross-script input.
        $positions = $h->kind === ClassificationKind::Clear ? [] : array_keys($input);
        self::pushFinding($findings, Family::HomoglyphConfusable, $h->kind, $h->sub, $positions);
        $mixedSub = HomoglyphConfusable::mixedScriptVerdict($input, self::profileIsIdentifierField($profile));
        if ($mixedSub !== null) {
            self::pushFinding($findings, Family::MixedScriptAdmissibility, ClassificationKind::Hazard, $mixedSub, array_keys($input));
        }

        $rtl = RtlInjection::detect($input);
        if ($rtl->sub !== null) {
            self::pushFinding($findings, Family::RtlInjection, ClassificationKind::Hazard, $rtl->sub, $rtl->positions);
        }

        $cb = ConfusableBidiCompound::detect($input);
        if ($cb->sub !== null) {
            self::pushFinding($findings, Family::ConfusableBidiCompound, ClassificationKind::Hazard, $cb->sub, $cb->positions);
        }

        $cd = CovertDisplayCompound::detect($input);
        if ($cd->sub !== null) {
            self::pushFinding($findings, Family::CovertDisplayCompound, ClassificationKind::Hazard, $cd->sub, $cd->positions);
        }

        $e = EmojiZwjIntegrity::detect($input);
        if (!$e->classify->isClear()) {
            self::pushFinding($findings, Family::EmojiZwjIntegrity, ClassificationKind::Hazard, $e->classify->tag(), $e->classify->positions());
        }

        $stvf = SkinToneVariationForgery::detect($input);
        if (!$stvf->classify->isClear()) {
            self::pushFinding($findings, Family::SkinToneVariationForgery, ClassificationKind::Hazard, $stvf->classify->tag(), $stvf->classify->positions());
        }

        $fd = FilenameDisguise::detect($input);
        if (!$fd->classify->isClear()) {
            self::pushFinding($findings, Family::FilenameDisguise, ClassificationKind::Hazard, $fd->classify->tag(), $fd->classify->positions());
        }

        $rd = RendererDivergence::detect($input);
        if (!$rd->classify->isClear()) {
            self::pushFinding($findings, Family::RendererDivergence, ClassificationKind::Hazard, $rd->classify->tag(), $rd->classify->positions());
        }

        $ssv = StreamSafeViolation::detect($input);
        if (!$ssv->classify->isClear()) {
            self::pushFinding($findings, Family::StreamSafeViolation, ClassificationKind::Hazard, $ssv->classify->tag(), $ssv->classify->positions());
        }

        $cem = CaseExpansionMismatch::detect($input);
        if (!$cem->classify->isClear()) {
            self::pushFinding($findings, Family::CaseExpansionMismatch, ClassificationKind::Hazard, $cem->classify->tag(), $cem->classify->positions());
        }

        $ifd = IdentifierFormDrift::detect($input);
        if (!$ifd->classify->isClear()) {
            self::pushFinding($findings, Family::IdentifierFormDrift, ClassificationKind::Hazard, $ifd->classify->tag(), $ifd->classify->positions());
        }

        $afd = AdmissibilityFormDrift::detect($input);
        if (!$afd->classify->isClear()) {
            self::pushFinding($findings, Family::AdmissibilityFormDrift, ClassificationKind::Hazard, $afd->classify->tag(), $afd->classify->positions());
        }

        $nb = NormalizationBomb::detect($input);
        if ($nb->sub !== null) {
            self::pushFinding($findings, Family::NormalizationBomb, ClassificationKind::Hazard, $nb->sub, $nb->positions);
        }

        $lci = LocaleCaseInversion::detect($input);
        if ($lci->sub !== null) {
            self::pushFinding($findings, Family::LocaleCaseInversion, ClassificationKind::Hazard, $lci->sub, $lci->positions);
        }

        $niw = NfcIdempotenceWitness::detect($input);
        if ($niw->sub !== null) {
            self::pushFinding($findings, Family::NfcIdempotenceWitness, ClassificationKind::Hazard, $niw->sub, $niw->positions);
        }

        $wcc = WidthClassConfusion::detect($input);
        if ($wcc->sub !== null) {
            self::pushFinding($findings, Family::WidthClassConfusion, ClassificationKind::Hazard, $wcc->sub, $wcc->positions);
        }

        // SourceDisplayDivergence judges the input as a unit, so it localises
        // nothing and carries an empty position list.
        $sdd = SourceDisplayDivergence::detect($input);
        if (!$sdd->classify->isClear()) {
            self::pushFinding($findings, Family::SourceDisplayDivergence, ClassificationKind::Hazard, $sdd->classify->tag(), []);
        }

        return new Verdict(array_values($input), $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    private static function malformedDecodeVerdict(Profile $profile, Mode $mode, Family $family, string $sub, int $offset): Verdict
    {
        $findings = [new Finding(self::reasonCode($family, $sub), $family, Severity::Moderate, [$offset], $sub, self::familySlug($family))];
        return new Verdict([], $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $bytes */
    public static function scanUtf8(Profile $profile, Mode $mode, array $bytes): Verdict
    {
        $reject = Utf8::firstInvalidOffset($bytes);
        if ($reject !== null) {
            return self::malformedDecodeVerdict($profile, $mode, Family::MalformedUtf8, $reject[1]->name, $reject[0]);
        }
        return self::scan($profile, $mode, Utf8::decodeToCodepoints($bytes));
    }

    /** @param list<int> $bytes */
    private static function readU16(array $bytes, int $offset, string $endian): int
    {
        return $endian === 'big' ? $bytes[$offset] * 0x100 + $bytes[$offset + 1] : $bytes[$offset] + $bytes[$offset + 1] * 0x100;
    }

    /** @param list<int> $bytes */
    private static function readU32(array $bytes, int $offset, string $endian): int
    {
        if ($endian === 'big') {
            return $bytes[$offset] * 0x1000000 + $bytes[$offset + 1] * 0x10000 + $bytes[$offset + 2] * 0x100 + $bytes[$offset + 3];
        }
        return $bytes[$offset] + $bytes[$offset + 1] * 0x100 + $bytes[$offset + 2] * 0x10000 + $bytes[$offset + 3] * 0x1000000;
    }

    /** @param list<int> $bytes @return array{0:?array,1:?string,2:?int} */
    private static function decodeUtf16Stream(array $bytes, string $endian): array
    {
        $input = [];
        $offset = 0;
        $count = count($bytes);
        while ($offset < $count) {
            if ($offset + 2 > $count) {
                return [null, 'TruncatedCodeUnit', $count];
            }
            $unit = self::readU16($bytes, $offset, $endian);
            $unitOffset = $offset;
            $offset += 2;
            if ($unit >= 0xD800 && $unit <= 0xDBFF) {
                if ($offset + 2 > $count) {
                    return [null, 'TruncatedSurrogatePair', $count];
                }
                $low = self::readU16($bytes, $offset, $endian);
                if ($low < 0xDC00 || $low > 0xDFFF) {
                    return [null, 'InvalidSurrogatePair', $offset];
                }
                $input[] = 0x10000 + ($unit - 0xD800) * 0x400 + ($low - 0xDC00);
                $offset += 2;
            } elseif ($unit >= 0xDC00 && $unit <= 0xDFFF) {
                return [null, 'LoneSurrogate', $unitOffset];
            } else {
                $input[] = $unit;
            }
        }
        return [$input, null, null];
    }

    /** @param list<int> $bytes @return array{0:?array,1:?string,2:?int} */
    private static function decodeUtf32Stream(array $bytes, string $endian): array
    {
        $count = count($bytes);
        if ($count % 4 !== 0) {
            return [null, 'TruncatedCodeUnit', $count];
        }
        $input = [];
        for ($offset = 0; $offset < $count; $offset += 4) {
            $cp = self::readU32($bytes, $offset, $endian);
            if ($cp >= 0xD800 && $cp <= 0xDFFF) {
                return [null, 'SurrogateCodepoint', $offset];
            }
            if ($cp > 0x10FFFF) {
                return [null, 'CodepointBeyondMax', $offset];
            }
            $input[] = $cp;
        }
        return [$input, null, null];
    }

    /** @param list<int> $bytes */
    private static function scanUtf16(Profile $profile, Mode $mode, array $bytes, string $endian): Verdict
    {
        [$input, $sub, $offset] = self::decodeUtf16Stream($bytes, $endian);
        if ($input === null) {
            return self::malformedDecodeVerdict($profile, $mode, Family::MalformedUtf16, $sub, $offset);
        }
        return self::scan($profile, $mode, $input);
    }

    /** @param list<int> $bytes */
    private static function scanUtf32(Profile $profile, Mode $mode, array $bytes, string $endian): Verdict
    {
        [$input, $sub, $offset] = self::decodeUtf32Stream($bytes, $endian);
        if ($input === null) {
            return self::malformedDecodeVerdict($profile, $mode, Family::MalformedUtf32, $sub, $offset);
        }
        return self::scan($profile, $mode, $input);
    }

    /** @param list<int> $bytes */
    public static function scanUtf16be(Profile $profile, Mode $mode, array $bytes): Verdict
    {
        return self::scanUtf16($profile, $mode, $bytes, 'big');
    }

    /** @param list<int> $bytes */
    public static function scanUtf16le(Profile $profile, Mode $mode, array $bytes): Verdict
    {
        return self::scanUtf16($profile, $mode, $bytes, 'little');
    }

    /** @param list<int> $bytes */
    public static function scanUtf32be(Profile $profile, Mode $mode, array $bytes): Verdict
    {
        return self::scanUtf32($profile, $mode, $bytes, 'big');
    }

    /** @param list<int> $bytes */
    public static function scanUtf32le(Profile $profile, Mode $mode, array $bytes): Verdict
    {
        return self::scanUtf32($profile, $mode, $bytes, 'little');
    }

    /** @param list<int> $input */
    public static function scanDefault(Profile $profile, array $input): Verdict
    {
        return self::scan($profile, Mode::Enforce, $input);
    }

    /** @return array<string,mixed> */
    public static function findingToWire(Finding $finding): array
    {
        return [
            'code' => $finding->code,
            'family' => self::familySlug($finding->family),
            'severity' => $finding->severity->value,
            'positions' => $finding->positions,
            'sub_threat' => $finding->subThreat,
            'detail' => $finding->detail,
        ];
    }

    /** @return array<string,mixed> */
    public static function verdictToWire(Verdict $verdict): array
    {
        return [
            'action' => $verdict->action->value,
            'profile' => $verdict->profile->value,
            'mode' => $verdict->mode->value,
            'input' => $verdict->input,
            'findings' => array_map([self::class, 'findingToWire'], $verdict->findings),
            'normalized' => $verdict->normalized,
        ];
    }

    public static function verdictToJson(Verdict $verdict): string
    {
        return json_encode(self::verdictToWire($verdict), JSON_UNESCAPED_SLASHES);
    }

    /** @param list<int> $input */
    public static function scanBip39(Profile $profile, Mode $mode, array $input): Verdict
    {
        $b = Bip39Canonical::detect($input);
        $findings = [];
        if ($b->sub !== null) {
            self::pushFinding($findings, Family::Bip39Canonical, ClassificationKind::Hazard, $b->sub, $b->positions);
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, $b->canonical);
    }

    /** @param list<int> $input */
    public static function scanHashInput(Profile $profile, Mode $mode, array $input): Verdict
    {
        $h = HashInputStability::detect($input);
        $findings = [];
        if (!$h->classify->isClear()) {
            self::pushFinding($findings, Family::HashInputStability, ClassificationKind::Hazard, $h->classify->tag(), $h->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, $h->stableForm);
    }

    /** @param list<int> $input */
    public static function scanAiWatermark(Profile $profile, Mode $mode, array $input): Verdict
    {
        $a = AiWatermarkDetectability::detect($input);
        $findings = [];
        if (!$a->classify->isClear()) {
            self::pushFinding($findings, Family::AiWatermarkDetectability, ClassificationKind::Hazard, $a->classify->tag(), $a->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanEmojiZwjIntegrity(Profile $profile, Mode $mode, array $input): Verdict
    {
        $e = EmojiZwjIntegrity::detect($input);
        $findings = [];
        if (!$e->classify->isClear()) {
            self::pushFinding($findings, Family::EmojiZwjIntegrity, ClassificationKind::Hazard, $e->classify->tag(), $e->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanSkinToneVariationForgery(Profile $profile, Mode $mode, array $input): Verdict
    {
        $s = SkinToneVariationForgery::detect($input);
        $findings = [];
        if (!$s->classify->isClear()) {
            self::pushFinding($findings, Family::SkinToneVariationForgery, ClassificationKind::Hazard, $s->classify->tag(), $s->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanRendererDivergence(Profile $profile, Mode $mode, array $input): Verdict
    {
        $r = RendererDivergence::detect($input);
        $findings = [];
        if (!$r->classify->isClear()) {
            self::pushFinding($findings, Family::RendererDivergence, ClassificationKind::Hazard, $r->classify->tag(), $r->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanSourceDisplayDivergence(Profile $profile, Mode $mode, array $input): Verdict
    {
        $s = SourceDisplayDivergence::detect($input);
        $findings = [];
        if (!$s->classify->isClear()) {
            self::pushFinding($findings, Family::SourceDisplayDivergence, ClassificationKind::Hazard, $s->classify->tag(), $s->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanFilenameDisguise(Profile $profile, Mode $mode, array $input): Verdict
    {
        $f = FilenameDisguise::detect($input);
        $findings = [];
        if (!$f->classify->isClear()) {
            self::pushFinding($findings, Family::FilenameDisguise, ClassificationKind::Hazard, $f->classify->tag(), $f->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanIdentifierFormDrift(Profile $profile, Mode $mode, array $input): Verdict
    {
        $d = IdentifierFormDrift::detect($input);
        $findings = [];
        if (!$d->classify->isClear()) {
            self::pushFinding($findings, Family::IdentifierFormDrift, ClassificationKind::Hazard, $d->classify->tag(), $d->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanAdmissibilityFormDrift(Profile $profile, Mode $mode, array $input): Verdict
    {
        $d = AdmissibilityFormDrift::detect($input);
        $findings = [];
        if (!$d->classify->isClear()) {
            self::pushFinding($findings, Family::AdmissibilityFormDrift, ClassificationKind::Hazard, $d->classify->tag(), $d->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanCaseExpansionMismatch(Profile $profile, Mode $mode, array $input): Verdict
    {
        $c = CaseExpansionMismatch::detect($input);
        $findings = [];
        if (!$c->classify->isClear()) {
            self::pushFinding($findings, Family::CaseExpansionMismatch, ClassificationKind::Hazard, $c->classify->tag(), $c->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }

    /** @param list<int> $input */
    public static function scanForms(Profile $profile, Mode $mode, array $input): Verdict
    {
        $findings = [];
        foreach ([
            [Family::LocaleCaseInversion, LocaleCaseInversion::detect($input)],
            [Family::NfcIdempotenceWitness, NfcIdempotenceWitness::detect($input)],
            [Family::NormalizationBomb, NormalizationBomb::detect($input)],
        ] as [$family, $v]) {
            if ($v->sub !== null) {
                self::pushFinding($findings, $family, ClassificationKind::Hazard, $v->sub, $v->positions);
            }
        }
        $stream = StreamSafeViolation::detect($input);
        if (!$stream->classify->isClear()) {
            self::pushFinding($findings, Family::StreamSafeViolation, ClassificationKind::Hazard, $stream->classify->tag(), $stream->classify->positions());
        }
        return new Verdict($input, $profile, $mode, self::selectAction($profile, $mode, $findings), $findings, null);
    }
}
