<?php

declare(strict_types=1);

// PSR-4-style autoloader for the `UnicodePhp` namespace, mapping to this
// `src/` directory. No Composer / network dependency: the security suite is a
// self-contained deployment surface that reads only files under `ports/php/`.

spl_autoload_register(static function (string $class): void {
    $shared = [
        'UnicodePhp\\Utf8RejectKind' => __DIR__ . '/Strict.php',
        'UnicodePhp\\Security\\Family' => __DIR__ . '/Security/Calculus.php',
        'UnicodePhp\\Security\\Severity' => __DIR__ . '/Security/Calculus.php',
        'UnicodePhp\\Security\\AdversaryTier' => __DIR__ . '/Security/Calculus.php',
        'UnicodePhp\\Security\\ClassificationKind' => __DIR__ . '/Security/Calculus.php',
        'UnicodePhp\\Security\\Calculus' => __DIR__ . '/Security/Calculus.php',
        'UnicodePhp\\Security\\HazardPosition' => __DIR__ . '/Security/Calculus.php',
        'UnicodePhp\\Security\\KeyValueAttribution' => __DIR__ . '/Security/Calculus.php',
        'UnicodePhp\\Security\\Crypto\\AiWatermarkCueClass' => __DIR__ . '/Security/Crypto/AiWatermarkDetectability.php',
        'UnicodePhp\\Security\\Crypto\\AiWatermarkSubThreat' => __DIR__ . '/Security/Crypto/AiWatermarkDetectability.php',
        'UnicodePhp\\Security\\Crypto\\AiWatermarkClassification' => __DIR__ . '/Security/Crypto/AiWatermarkDetectability.php',
        'UnicodePhp\\Security\\Crypto\\AiWatermarkVerdict' => __DIR__ . '/Security/Crypto/AiWatermarkDetectability.php',
        'UnicodePhp\\Security\\Crypto\\AiWatermarkContext' => __DIR__ . '/Security/Crypto/AiWatermarkDetectability.php',
        'UnicodePhp\\Security\\Crypto\\RfcRule' => __DIR__ . '/Security/Crypto/HashInputStability.php',
        'UnicodePhp\\Security\\Crypto\\Context' => __DIR__ . '/Security/Crypto/HashInputStability.php',
        'UnicodePhp\\Security\\Crypto\\SubThreat' => __DIR__ . '/Security/Crypto/HashInputStability.php',
        'UnicodePhp\\Security\\Crypto\\Classification' => __DIR__ . '/Security/Crypto/HashInputStability.php',
        'UnicodePhp\\Security\\Crypto\\HashInputVerdict' => __DIR__ . '/Security/Crypto/HashInputStability.php',
        'UnicodePhp\\Security\\Form\\CaseExpansionMismatchSubThreat' => __DIR__ . '/Security/Form/CaseExpansionMismatch.php',
        'UnicodePhp\\Security\\Form\\CaseExpansionMismatchClassification' => __DIR__ . '/Security/Form/CaseExpansionMismatch.php',
        'UnicodePhp\\Security\\Form\\CaseExpansionMismatchVerdict' => __DIR__ . '/Security/Form/CaseExpansionMismatch.php',
        'UnicodePhp\\Security\\Form\\CaseExpansionMismatch' => __DIR__ . '/Security/Form/CaseExpansionMismatch.php',
        'UnicodePhp\\Security\\Form\\SubThreat' => __DIR__ . '/Security/Form/StreamSafeViolation.php',
        'UnicodePhp\\Security\\Form\\Classification' => __DIR__ . '/Security/Form/StreamSafeViolation.php',
        'UnicodePhp\\Security\\Form\\StreamSafeVerdict' => __DIR__ . '/Security/Form/StreamSafeViolation.php',
        'UnicodePhp\\Security\\Identity\\Locale' => __DIR__ . '/Security/Identity/Ucd.php',
        'UnicodePhp\\Security\\Identity\\BidiStrong' => __DIR__ . '/Security/Identity/Ucd.php',
        'UnicodePhp\\Security\\Identity\\RestrictionLevel' => __DIR__ . '/Security/Identity/Ucd.php',
        'UnicodePhp\\Security\\Identity\\EmojiZwjSubThreat' => __DIR__ . '/Security/Identity/EmojiZwjIntegrity.php',
        'UnicodePhp\\Security\\Identity\\EmojiZwjClassification' => __DIR__ . '/Security/Identity/EmojiZwjIntegrity.php',
        'UnicodePhp\\Security\\Identity\\EmojiZwjVerdict' => __DIR__ . '/Security/Identity/EmojiZwjIntegrity.php',
        'UnicodePhp\\Security\\Identity\\SkinToneVariationForgerySubThreat' => __DIR__ . '/Security/Identity/SkinToneVariationForgery.php',
        'UnicodePhp\\Security\\Identity\\SkinToneVariationForgeryClassification' => __DIR__ . '/Security/Identity/SkinToneVariationForgery.php',
        'UnicodePhp\\Security\\Identity\\SkinToneVariationForgeryVerdict' => __DIR__ . '/Security/Identity/SkinToneVariationForgery.php',
        'UnicodePhp\\Security\\Identity\\SkinToneVariationForgery' => __DIR__ . '/Security/Identity/SkinToneVariationForgery.php',
        'UnicodePhp\\Security\\Display\\RendererDivergenceSubThreat' => __DIR__ . '/Security/Display/RendererDivergence.php',
        'UnicodePhp\\Security\\Display\\RendererDivergenceClassification' => __DIR__ . '/Security/Display/RendererDivergence.php',
        'UnicodePhp\\Security\\Display\\RendererDivergenceVerdict' => __DIR__ . '/Security/Display/RendererDivergence.php',
        'UnicodePhp\\Security\\Display\\RendererDivergence' => __DIR__ . '/Security/Display/RendererDivergence.php',
        'UnicodePhp\\Security\\Display\\FilenameDisguiseSubThreat' => __DIR__ . '/Security/Display/FilenameDisguise.php',
        'UnicodePhp\\Security\\Display\\FilenameDisguiseClassification' => __DIR__ . '/Security/Display/FilenameDisguise.php',
        'UnicodePhp\\Security\\Display\\FilenameDisguiseVerdict' => __DIR__ . '/Security/Display/FilenameDisguise.php',
        'UnicodePhp\\Security\\Display\\FilenameDisguise' => __DIR__ . '/Security/Display/FilenameDisguise.php',
        'UnicodePhp\\Security\\Boundary\\IdentifierFormDriftSubThreat' => __DIR__ . '/Security/Boundary/IdentifierFormDrift.php',
        'UnicodePhp\\Security\\Boundary\\IdentifierFormDriftClassification' => __DIR__ . '/Security/Boundary/IdentifierFormDrift.php',
        'UnicodePhp\\Security\\Boundary\\IdentifierFormDriftVerdict' => __DIR__ . '/Security/Boundary/IdentifierFormDrift.php',
        'UnicodePhp\\Security\\Boundary\\IdentifierFormDrift' => __DIR__ . '/Security/Boundary/IdentifierFormDrift.php',
        'UnicodePhp\\Segmentation\\Gcb' => __DIR__ . '/Segmentation/GraphemeTables.php',
        'UnicodePhp\\Segmentation\\Incb' => __DIR__ . '/Segmentation/GraphemeTables.php',
        'UnicodePhp\\Segmentation\\EpicState' => __DIR__ . '/Segmentation/Grapheme.php',
        'UnicodePhp\\Segmentation\\IncbState' => __DIR__ . '/Segmentation/Grapheme.php',
        'UnicodePhp\\Segmentation\\GraphemeState' => __DIR__ . '/Segmentation/Grapheme.php',
    ];
    if (isset($shared[$class])) {
        require $shared[$class];
        return;
    }

    $prefix = 'UnicodePhp\\';
    $prefixLength = strlen($prefix);
    if (strncmp($class, $prefix, $prefixLength) !== 0) {
        return;
    }
    $relative = substr($class, $prefixLength);
    $path = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});
