//! Cross-port differential runner — Rust side.
//!
//! Two modes:
//!
//!   1. Generate corpus.  Writes /tmp/diff_corpus.jsonl with N
//!      input sequences as `{"id":<n>,"cps":[<u32>,…]}` JSONL.
//!      The corpus file is the SHARED artifact every port reads.
//!
//!   2. Run detect on corpus.  Reads /tmp/diff_corpus.jsonl,
//!      runs `homoglyph_confusable::detect` on each input, emits
//!      one JSONL line to stdout per input:
//!
//!        {"id":<n>,"cps":[…],"kind":"…","sub":"…","target":"…"}
//!
//! The Python and C++ ports run identical mode-2 runners against
//! the same corpus.  A bash orchestrator diffs the three outputs.
//! Any byte-level divergence is a port-drift bug.
//!
//! Generate corpus:
//!     cargo test --test diff_runner --release diff_gen_corpus -- --nocapture
//! Run against corpus (capture verdicts):
//!     cargo test --test diff_runner --release diff_run_against_corpus -- --nocapture > /tmp/rust_diff.jsonl

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use unicode_rust::security::identity::homoglyph_confusable as h;
use unicode_rust::security::identity::homoglyph_confusable::SubThreat;
use unicode_rust::security::ClassificationKind;

const CORPUS_PATH: &str = "/tmp/diff_corpus.jsonl";

// ──────────────────────────────────────────────────────────────────────
// Shared cross-port PRNG.  xorshift64 with seed 0xC0FFEE_1234_5678.
// Same constants in python_runner.py and cpp diff_runner.cpp.
// ──────────────────────────────────────────────────────────────────────

const SEED: u64 = 0xC0FFEE_1234_5678;
const N_INPUTS: usize = 100_000;
const MAX_LEN: usize = 32;

struct Xorshift(u64);

impl Xorshift {
    fn new() -> Self {
        Self(SEED)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

// The nine explicit bidi controls: embeddings, overrides, isolates, PDF, PDI.
const BIDI_CONTROLS: [u32; 9] = [
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
];
// Space plus the ASCII code syntax the bidi purpose rule treats as content
// that makes a span purposeless.
const CODE_SYNTAX_OR_SPACE: [u32; 12] = [
    0x20, 0x22, 0x27, 0x28, 0x29, 0x2F, 0x3B, 0x3D, 0x5B, 0x5D, 0x7B, 0x7D,
];
// Latin letters whose skeleton is ASCII (dotless i, long s, script g) plus
// dotless j, which is restricted rather than confusable.
const ASCII_CONFUSABLE_LATIN: [u32; 4] = [0x0131, 0x017F, 0x0237, 0x0261];
// Separators that end an identifier token: space, dot, underscore, hyphen, comma.
const TOKEN_SEPARATORS: [u32; 5] = [0x20, 0x2E, 0x5F, 0x2D, 0x2C];
const GREEK_LOOKALIKES: [u32; 4] = [0x03B1, 0x03BF, 0x03BD, 0x03C1];
const LATIN_CYRILLIC_LOOKALIKES: [u32; 14] = [
    0x61, 0x65, 0x6F, 0x70, 0x63, 0x79, 0x78, 0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443,
    0x0445,
];
const HEBREW_LETTER_COUNT: u64 = 27; // U+05D0..U+05EA
const ARABIC_LETTER_COUNT: u64 = 36; // U+0627..U+064A
// Twenty classes: 0-13 as documented on `gen_input`, 14-19 seeded.
const INPUT_CLASS_COUNT: u64 = 20;
const SEED_PAD_POOL_COUNT: u64 = 5;

// One input per detector-fixture case that fires a rung, the same table as
// scripts/internal/generate_differential_corpus.py `SEEDS`, in the same order;
// the two streams are checked equal over the committed corpus.
const SEEDS: &[&[u32]] = &[
    &[0xFB01], // admissibility_form_drift/fi-ligature-drift
    &[0x1112, 0x1161, 0x11AB], // admissibility_form_drift/jamo-sequence-drift
    &[0x0069, 0x0066, 0x0020, 0x202E, 0x0029, 0x007B], // bidi_control_balance/unbalanced-embedding
    &[0x202C], // bidi_control_balance/orphan-pop
    &[0x2066], // bidi_control_balance/unbalanced-isolate
    &[0x00DF], // case_expansion_mismatch/sharp-s-upper
    &[0xFB01], // case_expansion_mismatch/fi-ligature-upper
    &[0xFB03], // case_expansion_mismatch/ffi-ligature-upper
    &[0x0130], // case_expansion_mismatch/dotted-I-lower
    &[0x202E, 0x0430], // confusable_bidi_compound/confusable-in-override
    &[0x2066, 0x03BF], // confusable_bidi_compound/confusable-in-isolate
    &[0x202E, 0x0041, 0xFE00], // covert_display_compound/bidi-plus-unregistered-vs
    &[0x202E, 0x0041, 0xE0001], // covert_display_compound/bidi-plus-tag-block
    &[0x1F600, 0x200D, 0x200D, 0x1F600], // emoji_zwj_integrity/double-zwj-hazard
    &[0x1F600, 0x200D, 0x0061], // emoji_zwj_integrity/non-emoji-injection-ascii-hazard
    &[0x1F600, 0x200D, 0x1F4BB], // emoji_zwj_integrity/grinning-laptop-non-emoji-injection-hazard
    &[0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF], // emoji_zwj_integrity/skin-tone-overflow-hazard
    &[0x1F468, 0x200D, 0x1F469], // emoji_zwj_integrity/unregistered-man-woman-hazard
    &[0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468], // emoji_zwj_integrity/over-length-chain-hazard
    &[0x0064, 0x006F, 0x0063, 0x0075, 0x006D, 0x0065, 0x006E, 0x0074, 0x202E, 0x0074, 0x0078, 0x0074, 0x002E, 0x0065, 0x0078, 0x0065], // filename_disguise/rlo-flip-hazard
    &[0x0064, 0x006F, 0x0063, 0x2067, 0x0074, 0x0078, 0x0074, 0x002E, 0x0065, 0x0078, 0x0065, 0x2069], // filename_disguise/isolate-flip-hazard
    &[0x0066, 0x0069, 0x006C, 0x0065, 0x002E, 0xFF25, 0xFF38, 0xFF25], // filename_disguise/fullwidth-ext-hazard
    &[0x0066, 0x0069, 0x006C, 0x0065, 0x002E, 0x0065, 0x0301, 0x0078, 0x0065], // filename_disguise/combining-in-ext-hazard
    &[0x0073, 0x0065, 0x0074, 0x0075, 0x0070, 0x002E, 0x0074, 0x0061, 0x0072, 0x002E, 0x0067, 0x007A, 0x002E, 0x0073, 0x0069, 0x0067], // filename_disguise/triple-extension-hazard
    &[0x004E, 0x0065, 0x0074, 0x0068, 0x0065, 0x0072, 0x0435, 0x0075, 0x006D], // homoglyph_confusable/nethereum-cyrillic-e-target
    &[0x0430, 0x0070, 0x0070, 0x006C, 0x0065], // homoglyph_confusable/apple-cyrillic-a-target
    &[0x00E9, 0x0074, 0x0068, 0x0065, 0x0072, 0x0065, 0x0075, 0x006D], // homoglyph_confusable/ethereum-precomposed-accent-target
    &[0x1D400, 0x1D429, 0x1D429, 0x1D425, 0x1D41E], // homoglyph_confusable/math-bold-apple-target-priority
    &[0xFF30, 0xFF41, 0xFF59, 0xFF50, 0xFF41, 0xFF4C], // homoglyph_confusable/fullwidth-paypal-target-priority
    &[0x0065, 0x0078, 0x0070, 0x0072, 0x0065, 0x00DF], // homoglyph_confusable/express-sharp-s-full-casefold-target
    &[0x0065, 0x0078, 0x0070, 0x0072, 0x0065, 0x03B2], // homoglyph_confusable/express-beta-confusable-full-casefold-target
    &[0x0065, 0x0301], // homoglyph_confusable/decomposed-e-acute
    &[0x1D400], // homoglyph_confusable/math-bold-a
    &[0xFF21], // homoglyph_confusable/fullwidth-a
    &[0x0061, 0x0062, 0x0561, 0x0562], // homoglyph_confusable/latin-armenian-cross-script-mix
    &[0xE000], // homoglyph_confusable/private-use-restriction-low
    &[0xFDD0], // homoglyph_confusable/noncharacter-restriction-low
    &[0x0061, 0x0064, 0x006D, 0x0131, 0x006E], // homoglyph_confusable/dotless-i-admin-ascii-confusable
    &[0x1D44E], // identifier_form_drift/math-italic-a-shift
    &[0xFF21], // identifier_form_drift/fullwidth-A-shift
    &[0x24B6], // identifier_form_drift/circled-A-shift
    &[0xFB01], // identifier_form_drift/fi-ligature-shift
    &[0x2163], // identifier_form_drift/roman-iv-shift
    &[0x0061, 0x0062, 0x03B1, 0x03B2], // mixed_script_admissibility/latin-greek-script-mix
    &[0x004E, 0x0065, 0x0074, 0x0068, 0x0065, 0x0072, 0x0435, 0x0075, 0x006D], // mixed_script_admissibility/latin-cyrillic-target-match-also-mixed
    &[0x0061, 0x0062, 0x0561, 0x0562], // mixed_script_admissibility/latin-armenian-script-mix-other
    &[0x0061, 0x0062, 0x0E01, 0x0E02], // mixed_script_admissibility/latin-thai-script-mix-other
    &[0xFDD0], // noncharacter_control/bmp-noncharacter
    &[0x10FFFF], // noncharacter_control/plane-end-noncharacter
    &[0x0041, 0x0000, 0x0042], // noncharacter_control/c0-control
    &[0x0041, 0x0080, 0x0042], // noncharacter_control/c1-control
    &[0x1F600, 0xFE0F], // renderer_divergence/variation-selector-variance
    &[0x1F468, 0x200D, 0x1F469], // renderer_divergence/unregistered-zwj-variance
    &[0x0061, 0x0301, 0x0302, 0x0303, 0x0304], // renderer_divergence/combining-stack-overflow-zalgo
    &[0xFF21], // renderer_divergence/fullwidth-variance
    &[0x0041, 0x0042, 0x05D0, 0x05D1], // renderer_divergence/mixed-direction-variance
    &[0x0041, 0x202E, 0x0042], // rtl_injection/rlo-in-ltr
    &[0x0041, 0x202B, 0x0042, 0x0043, 0x202C], // rtl_injection/rle-in-ltr
    &[0x0041, 0x2066, 0x0042, 0x2069], // rtl_injection/lri-in-ltr
    &[0x05D0, 0x0042, 0x0043], // rtl_injection/field-takeover-hebrew
    &[0x0627, 0x0042, 0x0043], // rtl_injection/field-takeover-arabic
    &[0x0041, 0x0042, 0x05D0, 0x0044], // rtl_injection/mid-stream-hebrew
    &[0x0041, 0x0042, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x0044], // rtl_injection/overflow-hebrew
    &[0xE0041, 0xE0042], // source_display_divergence/tag-block-passthrough
    &[0x0041, 0xFE0F], // source_display_divergence/variation-selector-passthrough
    &[0x0048, 0x200B, 0x0069], // source_display_divergence/zero-width-passthrough
    &[0x202E, 0x0041], // source_display_divergence/bidi-control-passthrough
    &[0x2066, 0x0041, 0x2069], // source_display_divergence/bidi-control-balanced-passthrough
    &[0x004E, 0x0065, 0x0074, 0x0068, 0x0065, 0x0072, 0x0435, 0x0075, 0x006D], // source_display_divergence/identifier-homoglyph-passthrough
    &[0x0041, 0xFE0F, 0x200B], // source_display_divergence/compound-vs-plus-zero-width
    &[0xE0041, 0xE0042, 0x200B], // source_display_divergence/compound-tag-plus-zero-width
    &[0x00C0, 0x0080], // surrogate_reassembly/invalid-start-byte
    &[0x00E0, 0x0080, 0x00AF], // surrogate_reassembly/overlong
    &[0x00ED, 0x00A0, 0x0080], // surrogate_reassembly/cesu8-surrogate
    &[0x00C3], // surrogate_reassembly/truncated
    &[0xE0041, 0xE0042], // tag_block_payload/tag-ascii-payload
    &[0xE0001, 0xE0041], // tag_block_payload/language-tag-revival
    &[0x0048, 0xE0041], // tag_block_payload/tag-mixed-block
    &[0xE007F], // tag_block_payload/bare-tag-present
    &[0x0041, 0xFE0F], // variation_selector_payload/vs16-on-latin-illegal-target
    &[0x4E00, 0xFE04, 0xFE01], // variation_selector_payload/pair-aligned-direct-payload
    &[0x0061, 0x200B, 0x0062], // zero_width_payload/bare-zero-width
    &[0x0061, 0x200C, 0x0062], // zero_width_payload/latin-bare-zwnj
    &[0x200C, 0x0061], // zero_width_payload/zwnj-head-position
    // Rungs the detector fixtures leave thin or unreached.
    &[0x00F4, 0x0090, 0x0080, 0x0080], // surrogate_reassembly/CodepointBeyondMax
    &[0x0061, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301], // stream_safe_violation/StreamSafeOverrun
    &[0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB], // normalization_bomb/NfkdHighExpansion
    &[0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82], // normalization_bomb/NfdHighExpansion
    &[0xFDFA], // normalization_bomb/SingleCpBlowup
    &[0x1F600, 0xFE0E], // skin_tone_variation_forgery/ForcedTextStyle
    &[0x1F3FB, 0x1F3FB], // skin_tone_variation_forgery/InvalidSkinToneTarget
    &[0x004A, 0x0300], // locale_case_inversion/LithuanianCaseDivergence
    &[0x4E00, 0xFE00, 0xFE00, 0xFE00, 0xFE00], // variation_selector_payload/RepeatedBase
    &[0x0061, 0x2060, 0x0062], // zero_width_payload/WordJoinerInjection
    &[0x0061, 0x202F, 0x0062, 0x202F], // zero_width_payload/AiWatermarkNNBSP
    &[0x0061, 0xFFF9, 0x0062, 0xFFFB], // zero_width_payload/AnnotationMisuse
    &[0x0061, 0x200B, 0x0062, 0x200B], // zero_width_payload/BinaryPayload
    &[0x1F600, 0xFE0F, 0x0041, 0xFE00], // variation_selector_payload/EmbeddedAfterRegistered
];

fn pick_seed(rng: &mut Xorshift) -> &'static [u32] {
    SEEDS[(rng.next_u64() % SEEDS.len() as u64) as usize]
}

// One codepoint of seed context from pool 0-4: ASCII lower, ASCII
// alphanumeric, Hebrew, Latin-Cyrillic look-alike, code syntax or space.
fn pad_codepoint(rng: &mut Xorshift, pool: u64) -> u32 {
    match pool {
        0 => ascii_lower(rng),
        1 => ascii_alnum(rng),
        2 => hebrew_letter(rng),
        3 => pick(rng, &LATIN_CYRILLIC_LOOKALIKES),
        _ => pick(rng, &CODE_SYNTAX_OR_SPACE),
    }
}

// A detector-fixture seed at a random offset inside random context, with a
// second seed appended one time in three. Same draws, same order as the
// Python `seeded_input`.
fn seeded_input(rng: &mut Xorshift) -> Vec<u32> {
    let seed = pick_seed(rng);
    if seed.len() >= MAX_LEN {
        return seed[..MAX_LEN].to_vec();
    }
    // One seeded input in four is the bare seed, as in the Python generator.
    let bare = rng.next_u64() % 4 == 0;
    let pad_total = if bare {
        0
    } else {
        (rng.next_u64() % (MAX_LEN - seed.len() + 1) as u64) as usize
    };
    let prefix_len = (rng.next_u64() % (pad_total + 1) as u64) as usize;
    let pool = rng.next_u64() % SEED_PAD_POOL_COUNT;
    let mut out: Vec<u32> = Vec::with_capacity(MAX_LEN);
    for _index in 0..prefix_len {
        out.push(pad_codepoint(rng, pool));
    }
    out.extend_from_slice(seed);
    for _index in 0..(pad_total - prefix_len) {
        out.push(pad_codepoint(rng, pool));
    }
    if rng.next_u64() % 3 == 0 {
        let second = pick_seed(rng);
        out.extend_from_slice(second);
    }
    out.truncate(MAX_LEN);
    out
}

fn ascii_alnum(rng: &mut Xorshift) -> u32 {
    let r = (rng.next_u64() % 62) as u32;
    if r < 26 {
        0x61 + r // a..z
    } else if r < 52 {
        0x41 + (r - 26) // A..Z
    } else {
        0x30 + (r - 52) // 0..9
    }
}

fn ascii_lower(rng: &mut Xorshift) -> u32 {
    0x61 + (rng.next_u64() % 26) as u32
}

fn hebrew_letter(rng: &mut Xorshift) -> u32 {
    0x05D0 + (rng.next_u64() % HEBREW_LETTER_COUNT) as u32
}

fn arabic_letter(rng: &mut Xorshift) -> u32 {
    0x0627 + (rng.next_u64() % ARABIC_LETTER_COUNT) as u32
}

fn pick(rng: &mut Xorshift, pool: &[u32]) -> u32 {
    pool[(rng.next_u64() % pool.len() as u64) as usize]
}

// Generate one input.  Fourteen classes, one per input:
//   0-3   pure ASCII letters + digits
//   4-5   Latin + Cyrillic look-alikes
//   6     math-alpha + fullwidth
//   7     combining marks / NFC drift
//   8     default-ignorable / whitespace
//   9     random valid scalar
//   10    bidi controls beside Hebrew, Arabic, Latin and code syntax
//   11    Latin identifier tokens carrying an ascii-confusable letter
//   12    running text whose tokens mix Latin, Cyrillic and Greek
//   13    grab-bag: every position draws its pool afresh
//   14-19 a detector-fixture seed in random context (`seeded_input`)
// The draw order is the contract with
// scripts/internal/generate_differential_corpus.py, which carries the same
// generator in Python for the committed cross-port corpus.
fn gen_input(rng: &mut Xorshift) -> Vec<u32> {
    let len = (rng.next_u64() as usize) % (MAX_LEN + 1); // 0..=MAX_LEN
    let class = (rng.next_u64() % INPUT_CLASS_COUNT) as u8;
    if class >= 14 {
        return seeded_input(rng);
    }
    let mut input = Vec::with_capacity(len);
    while input.len() < len {
        let cp: u32 = if class <= 3 {
            ascii_alnum(rng)
        } else if class <= 5 {
            // Latin + Cyrillic look-alikes
            pick(rng, &LATIN_CYRILLIC_LOOKALIKES)
        } else if class == 6 {
            // Math-alpha + fullwidth
            let r = rng.next_u64() % 2;
            if r == 0 {
                0x1D400 + (rng.next_u64() % 0x400) as u32
            } else {
                0xFF21 + (rng.next_u64() % 0x5A) as u32
            }
        } else if class == 7 {
            // Combining marks + NFC drift
            const COMBINING_OR_LATIN: [u32; 4] = [0x0300, 0x0301, 0x0308, 0x0061];
            let r = (rng.next_u64() % COMBINING_OR_LATIN.len() as u64) as usize;
            if COMBINING_OR_LATIN[r] == 0x0061 {
                0x0061 + (rng.next_u64() % 26) as u32
            } else {
                COMBINING_OR_LATIN[r]
            }
        } else if class == 8 {
            // Default-ignorable + whitespace
            const DEFAULT_IGNORABLE_OR_SPACE: [u32; 6] =
                [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202F];
            let r = (rng.next_u64() % DEFAULT_IGNORABLE_OR_SPACE.len() as u64) as usize;
            DEFAULT_IGNORABLE_OR_SPACE[r]
        } else if class == 9 {
            // Random valid scalar (skip surrogate range)
            let r = rng.next_u64() as u32 % 0x110000;
            if (0xD800..=0xDFFF).contains(&r) {
                r + 0x800
            } else {
                r
            }
        } else if class == 10 {
            // Bidi purpose: controls beside RTL letters, Latin and code syntax.
            let r = rng.next_u64() % 8;
            if r < 2 {
                pick(rng, &BIDI_CONTROLS)
            } else if r < 4 {
                hebrew_letter(rng)
            } else if r == 4 {
                arabic_letter(rng)
            } else if r < 7 {
                ascii_lower(rng)
            } else {
                pick(rng, &CODE_SYNTAX_OR_SPACE)
            }
        } else if class == 11 {
            // Latin identifier tokens carrying an ascii-confusable letter.
            let r = rng.next_u64() % 6;
            if r < 4 {
                ascii_lower(rng)
            } else if r == 4 {
                pick(rng, &ASCII_CONFUSABLE_LATIN)
            } else {
                pick(rng, &TOKEN_SEPARATORS)
            }
        } else if class == 12 {
            // Running text whose tokens mix Latin, Cyrillic and Greek.
            let r = rng.next_u64() % 5;
            if r < 2 {
                ascii_lower(rng)
            } else if r == 2 {
                pick(rng, &LATIN_CYRILLIC_LOOKALIKES)
            } else if r == 3 {
                pick(rng, &GREEK_LOOKALIKES)
            } else {
                pick(rng, &TOKEN_SEPARATORS)
            }
        } else {
            debug_assert_eq!(class, 13);
            // Grab-bag: every position draws its pool afresh.
            let r = rng.next_u64() % 6;
            if r == 0 {
                ascii_alnum(rng)
            } else if r == 1 {
                pick(rng, &BIDI_CONTROLS)
            } else if r == 2 {
                hebrew_letter(rng)
            } else if r == 3 {
                pick(rng, &ASCII_CONFUSABLE_LATIN)
            } else if r == 4 {
                pick(rng, &LATIN_CYRILLIC_LOOKALIKES)
            } else {
                pick(rng, &CODE_SYNTAX_OR_SPACE)
            }
        };
        input.push(cp);
    }
    input
}

fn verdict_to_jsonl(id: usize, input: &[u32]) -> String {
    let v = h::detect(input);
    let kind = match v.kind {
        ClassificationKind::Clear => "Clear",
        ClassificationKind::Hazard => "Hazard",
        ClassificationKind::Compound => "Compound",
        ClassificationKind::Informational => "Informational",
    };
    let (sub_tag, target) = match &v.sub {
        None => ("null".to_string(), "null".to_string()),
        Some(SubThreat::TargetMatch { target }) => (
            "\"TargetMatch\"".to_string(),
            format!("\"{}\"", target.replace('"', "\\\"")),
        ),
        Some(SubThreat::MathAlpha { first_cp, count }) => {
            std::hint::black_box((first_cp, count));
            ("\"MathAlpha\"".to_string(), "null".to_string())
        }
        Some(SubThreat::WidthClass { first_cp, count }) => {
            std::hint::black_box((first_cp, count));
            ("\"WidthClass\"".to_string(), "null".to_string())
        }
        Some(SubThreat::DecompositionSwap { first_diff_pos }) => {
            std::hint::black_box(first_diff_pos);
            ("\"DecompositionSwap\"".to_string(), "null".to_string())
        }
        Some(SubThreat::CrossScriptMix { script_count }) => {
            std::hint::black_box(script_count);
            ("\"CrossScriptMix\"".to_string(), "null".to_string())
        }
        Some(SubThreat::RestrictionLow { level }) => {
            std::hint::black_box(level);
            ("\"RestrictionLow\"".to_string(), "null".to_string())
        }
        Some(SubThreat::AsciiConfusable { skeleton }) => {
            std::hint::black_box(skeleton);
            ("\"AsciiConfusable\"".to_string(), "null".to_string())
        }
    };
    let cps_str: Vec<String> = input.iter().map(|cp| cp.to_string()).collect();
    format!(
        "{{\"id\":{},\"cps\":[{}],\"kind\":\"{}\",\"sub\":{},\"target\":{}}}",
        id,
        cps_str.join(","),
        kind,
        sub_tag,
        target,
    )
}

fn cps_to_json_array(cps: &[u32]) -> String {
    let s: Vec<String> = cps.iter().map(|cp| cp.to_string()).collect();
    format!("[{}]", s.join(","))
}

fn parse_corpus_line(line: &str) -> (usize, Vec<u32>) {
    // Minimal hand parser of `{"id":N,"cps":[a,b,c]}`.  No deps.
    let id_start = line.find("\"id\":").expect("id field") + 5;
    let id_end = line[id_start..].find(',').expect("id end") + id_start;
    let id: usize = line[id_start..id_end].parse().expect("id parse");
    let arr_start = line.find("\"cps\":[").expect("cps field") + 7;
    let arr_end = line[arr_start..].find(']').expect("cps end") + arr_start;
    let cps_str = &line[arr_start..arr_end];
    let cps: Vec<u32> = if cps_str.is_empty() {
        Vec::new()
    } else {
        cps_str
            .split(',')
            .map(|s| s.trim().parse().expect("cp parse"))
            .collect()
    };
    (id, cps)
}

#[test]
fn diff_gen_corpus() {
    // Mode 1 — generate the shared corpus.
    let mut f = File::create(CORPUS_PATH).expect("open corpus");
    let mut rng = Xorshift::new();
    for id in 0..N_INPUTS {
        let input = gen_input(&mut rng);
        writeln!(f, "{{\"id\":{},\"cps\":{}}}", id, cps_to_json_array(&input),)
            .expect("write corpus");
    }
    eprintln!("wrote {} entries to {}", N_INPUTS, CORPUS_PATH);
}

#[test]
fn diff_run_against_corpus() {
    // Mode 2 — read corpus, run detect, emit JSONL to stdout.
    let f = File::open(CORPUS_PATH)
        .expect("/tmp/diff_corpus.jsonl missing — run diff_gen_corpus first");
    let reader = BufReader::new(f);
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    for line in reader.lines() {
        let line = line.expect("read");
        let (id, cps) = parse_corpus_line(&line);
        let out_line = verdict_to_jsonl(id, &cps);
        writeln!(lock, "{}", out_line).expect("write");
    }
}
