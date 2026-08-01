<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Crypto\Bip39Canonical;
use UnicodePhp\Security\Form\LocaleCaseInversion;
use UnicodePhp\Security\Form\NfcIdempotenceWitness;
use UnicodePhp\Security\Form\NormalizationBomb;

assert_same_value(null, LocaleCaseInversion::detect([])->sub, 'locale empty');
assert_same_value(null, LocaleCaseInversion::detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])->sub, 'locale ascii');
assert_same_value('TurkishCaseDivergence', LocaleCaseInversion::detect([0x0049])->sub, 'locale I');
assert_same_value([0], LocaleCaseInversion::detect([0x0049])->positions, 'locale I pos');
assert_same_value('TurkishCaseDivergence', LocaleCaseInversion::detect([0x0130])->sub, 'locale dotted I');
assert_same_value('TurkishCaseDivergence', LocaleCaseInversion::detect([0x0049, 0x0300])->sub, 'locale priority');
assert_same_value('LithuanianCaseDivergence', LocaleCaseInversion::detect([0x004A, 0x0300])->sub, 'locale lt');

assert_same_value(null, NfcIdempotenceWitness::detect([])->sub, 'nfc empty');
assert_same_value(null, NfcIdempotenceWitness::detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])->sub, 'nfc ascii');
assert_same_value(null, NfcIdempotenceWitness::detect([0x00E9])->sub, 'nfc composed');
assert_same_value('NonNfcForm', NfcIdempotenceWitness::detect([0x0065, 0x0301])->sub, 'nfc decomposed');
assert_same_value([0], NfcIdempotenceWitness::detect([0x0065, 0x0301])->positions, 'nfc pos');
assert_same_value('NonNfkcCompatForm', NfcIdempotenceWitness::detect([0xFB01])->sub, 'nfkc ligature');

assert_same_value(null, NormalizationBomb::detect([])->sub, 'bomb empty');
assert_same_value(null, NormalizationBomb::detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])->sub, 'bomb ascii');
assert_same_value(null, NormalizationBomb::detect([0xD55C])->sub, 'bomb korean');
assert_same_value(null, NormalizationBomb::detect([0x2460])->sub, 'bomb circled');
assert_same_value('SingleCpBlowup', NormalizationBomb::detect([0xFDFA])->sub, 'bomb blowup');
assert_same_value([0], NormalizationBomb::detect([0xFDFA])->positions, 'bomb blowup pos');
assert_same_value('NfkdHighExpansion', NormalizationBomb::detect([0xFDFB])->sub, 'bomb nfkd');
assert_same_value('NfdHighExpansion', NormalizationBomb::detect([0x1F82])->sub, 'bomb nfd');

$abandon = [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E];
$about = [0x61, 0x62, 0x6F, 0x75, 0x74];
assert_same_value([0x61, 0x20, 0x62], Bip39Canonical::bip39Canonical([0x61, 0x20, 0x20, 0x62]), 'bip39 collapse');
assert_same_value([0x61], Bip39Canonical::bip39Canonical([0x41]), 'bip39 lower');
assert_same_value('TrailingWhitespace', Bip39Canonical::detect(array_merge($abandon, [0x20]))->sub, 'bip39 trailing');
assert_same_value('MixedCase', Bip39Canonical::detect([0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E])->sub, 'bip39 case');
assert_same_value('WhitespaceAnomaly', Bip39Canonical::detect(array_merge($abandon, [0x20, 0x20], $about))->sub, 'bip39 ws');
assert_same_value('NonNFKD', Bip39Canonical::detect([0xFB00])->sub, 'bip39 nfkd');
assert_same_value('WordlistMismatch', Bip39Canonical::detect([0x71, 0x7A, 0x71, 0x7A])->sub, 'bip39 word');
$mnemonic = [];
for ($i = 0; $i < 11; $i++) {
    foreach ($abandon as $cp) {
        $mnemonic[] = $cp;
    }
    $mnemonic[] = 0x20;
}
foreach ($about as $cp) {
    $mnemonic[] = $cp;
}
$verdict = Bip39Canonical::detect($mnemonic);
assert_same_value(null, $verdict->sub, 'bip39 clear');
assert_same_value('english', $verdict->language, 'bip39 lang');
assert_same_value(12, $verdict->wordCount, 'bip39 count');
