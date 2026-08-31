//! UCD-table-backed support modules for the identity-spoofing
//! detector family — NFC normalization, script lookup, UTS #39
//! identifier-status / restriction-level classification.
//!
//! All data is embedded at compile time from the bundled UCD
//! files in the port's `data/` directory.  Parsing happens lazily
//! on first access via `std::sync::OnceLock`.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

const UNICODE_DATA_RAW: &str = include_str!("../../../data/UnicodeData.txt");
const COMPOSITION_EXCLUSIONS_RAW: &str = include_str!("../../../data/CompositionExclusions.txt");
const SCRIPTS_RAW: &str = include_str!("../../../data/Scripts.txt");
const SCRIPT_EXTENSIONS_RAW: &str = include_str!("../../../data/ScriptExtensions.txt");
const IDENTIFIER_STATUS_RAW: &str = include_str!("../../../data/IdentifierStatus.txt");
const PROPERTY_VALUE_ALIASES_RAW: &str = include_str!("../../../data/PropertyValueAliases.txt");
const DERIVED_CORE_PROPERTIES_RAW: &str = include_str!("../../../data/DerivedCoreProperties.txt");

fn parse_hex(s: &str) -> Option<u32> {
    u32::from_str_radix(s.trim(), 16).ok()
}

/// Return the portion of `line` before the first `#` comment
/// character (or the whole line if no `#` appears), with leading
/// and trailing ASCII whitespace removed.
fn strip_comment_and_trim(line: &str) -> &str {
    let body = match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    };
    body.trim()
}

// ─────────────────────────────────────────────────────────────────────
// UnicodeData.txt — CCC + canonical decomposition
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct UcdEntry {
    pub ccc: u8,
    pub canonical_decomp: Option<Vec<u32>>,
    /// Compatibility decomposition (field 5 with a `<tag>` prefix), tag
    /// stripped.  Used by NFKD/NFKC only; `None` when the row has a
    /// canonical decomposition or none at all.
    pub compat_decomp: Option<Vec<u32>>,
}

fn parse_unicode_data() -> HashMap<u32, UcdEntry> {
    let mut out = HashMap::new();
    for line in UNICODE_DATA_RAW.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(';').collect();
        if fields.len() < 6 {
            continue;
        }
        let cp = match parse_hex(fields[0]) {
            Some(c) => c,
            None => continue,
        };
        let ccc = match fields[3].trim().parse::<u8>() {
            Ok(value) => value,
            Err(err) => panic!(
                "UnicodeData.txt: CCC field for U+{:04X} is not a u8 \
                 ({:?}): {}",
                cp, fields[3], err
            ),
        };
        let decomp_field = fields[5].trim();
        let mut canonical_decomp = None;
        let mut compat_decomp = None;
        if !decomp_field.is_empty() {
            if decomp_field.starts_with('<') {
                // Compatibility decomposition: strip the `<tag>` prefix,
                // keep the codepoints for NFKD/NFKC (not NFD/NFC).
                let after_tag = decomp_field
                    .split_once('>')
                    .map(|(_, rest)| rest)
                    .unwrap_or(decomp_field);
                let parts: Vec<u32> =
                    after_tag.split_whitespace().filter_map(parse_hex).collect();
                if !parts.is_empty() {
                    compat_decomp = Some(parts);
                }
            } else {
                let parts: Vec<u32> = decomp_field
                    .split_whitespace()
                    .filter_map(parse_hex)
                    .collect();
                if !parts.is_empty() {
                    canonical_decomp = Some(parts);
                }
            }
        }
        out.insert(
            cp,
            UcdEntry {
                ccc,
                canonical_decomp,
                compat_decomp,
            },
        );
    }
    out
}

pub fn ucd_table() -> &'static HashMap<u32, UcdEntry> {
    static T: OnceLock<HashMap<u32, UcdEntry>> = OnceLock::new();
    T.get_or_init(parse_unicode_data)
}

pub fn ccc(cp: u32) -> u8 {
    // UAX #44 § 5.7.4: codepoints absent from the listed CCC ranges
    // have Canonical_Combining_Class = 0 by definition (Not_Reordered).
    // This is the spec's `@missing` default for the Canonical_Combining_Class
    // property, not a catchall fallback for malformed input.
    match ucd_table().get(&cp) {
        Some(entry) => entry.ccc,
        None => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────
// DerivedBidiClass.txt — strong Bidi_Class lookup
//
// Mirrors `Unicode.Generated.DerivedBidiClass.lookup`: an explicit range
// wins; otherwise the last matching `@missing` default range wins;
// otherwise the codepoint is `L`.  Only the strong distinction (R, AL, L)
// is retained — every other Bidi_Class collapses to `Other`.
// ─────────────────────────────────────────────────────────────────────

const DERIVED_BIDI_RAW: &str = include_str!("../../../data/DerivedBidiClass.txt");

/// The strong Bidi_Class distinction the display layer needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BidiStrong {
    R,
    Al,
    L,
    Other,
}

/// Explicit ranges (sorted by lower bound) and `@missing` default ranges
/// (in file order; the last match wins), parsed from DerivedBidiClass.txt.
pub struct BidiTable {
    explicit: Vec<(u32, u32, BidiStrong)>,
    defaults: Vec<(u32, u32, BidiStrong)>,
}

fn strong_of_short(token: &str) -> BidiStrong {
    match token {
        "R" => BidiStrong::R,
        "AL" => BidiStrong::Al,
        "L" => BidiStrong::L,
        _ => BidiStrong::Other,
    }
}

fn strong_of_long(token: &str) -> BidiStrong {
    match token {
        "Right_To_Left" => BidiStrong::R,
        "Arabic_Letter" => BidiStrong::Al,
        "Left_To_Right" => BidiStrong::L,
        _ => BidiStrong::Other,
    }
}

fn parse_derived_bidi() -> BidiTable {
    let mut explicit: Vec<(u32, u32, BidiStrong)> = Vec::new();
    let mut defaults: Vec<(u32, u32, BidiStrong)> = Vec::new();
    for line in DERIVED_BIDI_RAW.lines() {
        if let Some(rest) = line.strip_prefix("# @missing:") {
            // `# @missing: LO..HI; Long_Class_Name`
            if let Some((range, cls)) = rest.split_once(';') {
                if let Some((lo, hi)) = parse_range_field(range) {
                    defaults.push((lo, hi, strong_of_long(cls.trim())));
                }
            }
            continue;
        }
        let body = match line.split_once('#') {
            Some((before, _)) => before,
            None => line,
        };
        let body = body.trim();
        if body.is_empty() {
            continue;
        }
        // `LO..HI ; SHORT` or `CP ; SHORT`
        if let Some((range, cls)) = body.split_once(';') {
            if let Some((lo, hi)) = parse_range_field(range) {
                explicit.push((lo, hi, strong_of_short(cls.trim())));
            }
        }
    }
    explicit.sort_by_key(|entry| entry.0);
    BidiTable { explicit, defaults }
}

pub fn bidi_table() -> &'static BidiTable {
    static T: OnceLock<BidiTable> = OnceLock::new();
    T.get_or_init(parse_derived_bidi)
}

/// Full `Bidi_Class` lookup (strong distinction only): explicit range
/// first, then the last matching `@missing` default, then `L`.
pub fn bidi_strong(cp: u32) -> BidiStrong {
    let table = bidi_table();
    // Binary search the sorted explicit ranges.
    let mut lo = 0usize;
    let mut hi = table.explicit.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (rlo, rhi, cls) = table.explicit[mid];
        if cp < rlo {
            hi = mid;
        } else if cp > rhi {
            lo = mid + 1;
        } else {
            return cls;
        }
    }
    // No explicit row: last matching `@missing` default wins, else `L`.
    let mut result = BidiStrong::L;
    for &(rlo, rhi, cls) in &table.defaults {
        if rlo <= cp && cp <= rhi {
            result = cls;
        }
    }
    result
}

/// True iff the codepoint's `Bidi_Class` is strong RTL (R or AL).
pub fn is_strong_rtl(cp: u32) -> bool {
    matches!(bidi_strong(cp), BidiStrong::R | BidiStrong::Al)
}

const DERIVED_JOINING_TYPE_RAW: &str = include_str!("../../../data/DerivedJoiningType.txt");

/// `Joining_Type`, the cursive-joining behaviour a character has in scripts
/// like Arabic. RFC 5892 Appendix A.1 uses it to decide whether a ZERO WIDTH
/// NON-JOINER sits in a position its script actually requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoiningType {
    JoinCausing,
    DualJoining,
    LeftJoining,
    RightJoining,
    Transparent,
    NonJoining,
}

fn joining_type_of_token(token: &str) -> JoiningType {
    match token {
        "C" => JoiningType::JoinCausing,
        "D" => JoiningType::DualJoining,
        "L" => JoiningType::LeftJoining,
        "R" => JoiningType::RightJoining,
        "T" => JoiningType::Transparent,
        _ => JoiningType::NonJoining,
    }
}

fn parse_joining_types() -> Vec<(u32, u32, JoiningType)> {
    let mut out: Vec<(u32, u32, JoiningType)> = Vec::new();
    for line in DERIVED_JOINING_TYPE_RAW.lines() {
        let body = match line.split_once('#') {
            Some((before, _)) => before,
            None => line,
        };
        let body = body.trim();
        if body.is_empty() {
            continue;
        }
        if let Some((range, class)) = body.split_once(';') {
            if let Some((lo, hi)) = parse_range_field(range) {
                out.push((lo, hi, joining_type_of_token(class.trim())));
            }
        }
    }
    out.sort_by_key(|entry| entry.0);
    out
}

fn joining_type_table() -> &'static Vec<(u32, u32, JoiningType)> {
    static T: OnceLock<Vec<(u32, u32, JoiningType)>> = OnceLock::new();
    T.get_or_init(parse_joining_types)
}

/// `Joining_Type` for one codepoint. The file's `@missing` line declares
/// `Non_Joining` over the whole space, so an unlisted codepoint is
/// `NonJoining`.
pub fn joining_type(cp: u32) -> JoiningType {
    let table = joining_type_table();
    let mut lo = 0usize;
    let mut hi = table.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (rlo, rhi, class) = table[mid];
        if cp < rlo {
            hi = mid;
        } else if cp > rhi {
            lo = mid + 1;
        } else {
            return class;
        }
    }
    JoiningType::NonJoining
}

/// True iff `cp` has Canonical_Combining_Class 9, the Virama used to request
/// an explicit conjunct in scripts like Devanagari.
pub fn is_virama(cp: u32) -> bool {
    ccc(cp) == 9
}

const EAST_ASIAN_WIDTH_RAW: &str = include_str!("../../../data/EastAsianWidth.txt");

/// UAX #11 `East_Asian_Width` class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EastAsianWidthClass {
    /// Ambiguous.
    A,
    /// Fullwidth.
    F,
    /// Halfwidth.
    H,
    /// Neutral.
    N,
    /// Narrow.
    Na,
    /// Wide.
    W,
}

fn east_asian_width_of_token(token: &str) -> EastAsianWidthClass {
    match token {
        "A" => EastAsianWidthClass::A,
        "F" => EastAsianWidthClass::F,
        "H" => EastAsianWidthClass::H,
        "Na" => EastAsianWidthClass::Na,
        "W" => EastAsianWidthClass::W,
        _ => EastAsianWidthClass::N,
    }
}

fn parse_east_asian_width() -> Vec<(u32, u32, EastAsianWidthClass)> {
    let mut out: Vec<(u32, u32, EastAsianWidthClass)> = Vec::new();
    for line in EAST_ASIAN_WIDTH_RAW.lines() {
        let body = match line.split_once('#') {
            Some((before, _)) => before,
            None => line,
        };
        let body = body.trim();
        if body.is_empty() {
            continue;
        }
        if let Some((range, class)) = body.split_once(';') {
            if let Some((lo, hi)) = parse_range_field(range) {
                out.push((lo, hi, east_asian_width_of_token(class.trim())));
            }
        }
    }
    out.sort_by_key(|entry| entry.0);
    out
}

fn east_asian_width_table() -> &'static Vec<(u32, u32, EastAsianWidthClass)> {
    static T: OnceLock<Vec<(u32, u32, EastAsianWidthClass)>> = OnceLock::new();
    T.get_or_init(parse_east_asian_width)
}

/// `East_Asian_Width` for one codepoint. The file's `@missing` line declares
/// `N` over the whole space, so an unlisted codepoint is Neutral.
pub fn east_asian_width(cp: u32) -> EastAsianWidthClass {
    let table = east_asian_width_table();
    let mut lo = 0usize;
    let mut hi = table.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (rlo, rhi, class) = table[mid];
        if cp < rlo {
            hi = mid;
        } else if cp > rhi {
            lo = mid + 1;
        } else {
            return class;
        }
    }
    EastAsianWidthClass::N
}

/// True iff the codepoint's `Bidi_Class` is strong LTR (L).
pub fn is_strong_ltr(cp: u32) -> bool {
    matches!(bidi_strong(cp), BidiStrong::L)
}

// ─────────────────────────────────────────────────────────────────────
// CompositionExclusions.txt — codepoints that must not recompose
// ─────────────────────────────────────────────────────────────────────

fn parse_composition_exclusions() -> HashSet<u32> {
    let mut out = HashSet::new();
    for line in COMPOSITION_EXCLUSIONS_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        if let Some(cp) = parse_hex(stripped) {
            out.insert(cp);
        }
    }
    out
}

pub fn composition_exclusions() -> &'static HashSet<u32> {
    static T: OnceLock<HashSet<u32>> = OnceLock::new();
    T.get_or_init(parse_composition_exclusions)
}

// ─────────────────────────────────────────────────────────────────────
// Composition table — derived from UnicodeData canonical decomps
// minus the exclusion set.  Inverse of the canonical-decomp map for
// pairs (starter, combiner).
// ─────────────────────────────────────────────────────────────────────

fn build_composition_table() -> HashMap<(u32, u32), u32> {
    let table = ucd_table();
    let exclusions = composition_exclusions();
    let mut out = HashMap::new();
    for (&cp, entry) in table {
        if let Some(ref decomp) = entry.canonical_decomp {
            if decomp.len() == 2 && !exclusions.contains(&cp) {
                // Singleton-decomposition exclusions: also skip cases
                // where the first character is a non-starter.
                if ccc(decomp[0]) == 0 {
                    out.insert((decomp[0], decomp[1]), cp);
                }
            }
        }
    }
    out
}

pub fn composition_table() -> &'static HashMap<(u32, u32), u32> {
    static T: OnceLock<HashMap<(u32, u32), u32>> = OnceLock::new();
    T.get_or_init(build_composition_table)
}

// ─────────────────────────────────────────────────────────────────────
// Hangul algorithmic decomposition + composition
// ─────────────────────────────────────────────────────────────────────

const HANGUL_S_BASE: u32 = 0xAC00;
const HANGUL_L_BASE: u32 = 0x1100;
const HANGUL_V_BASE: u32 = 0x1161;
const HANGUL_T_BASE: u32 = 0x11A7;
const HANGUL_L_COUNT: u32 = 19;
const HANGUL_V_COUNT: u32 = 21;
const HANGUL_T_COUNT: u32 = 28;
const HANGUL_N_COUNT: u32 = HANGUL_V_COUNT * HANGUL_T_COUNT;
const HANGUL_S_COUNT: u32 = HANGUL_L_COUNT * HANGUL_N_COUNT;

fn hangul_decompose(cp: u32, out: &mut Vec<u32>) -> bool {
    if cp < HANGUL_S_BASE || cp >= HANGUL_S_BASE + HANGUL_S_COUNT {
        return false;
    }
    let s_index = cp - HANGUL_S_BASE;
    let l = HANGUL_L_BASE + s_index / HANGUL_N_COUNT;
    let v = HANGUL_V_BASE + (s_index % HANGUL_N_COUNT) / HANGUL_T_COUNT;
    let t_index = s_index % HANGUL_T_COUNT;
    out.push(l);
    out.push(v);
    if t_index != 0 {
        out.push(HANGUL_T_BASE + t_index);
    }
    true
}

fn hangul_compose(a: u32, b: u32) -> Option<u32> {
    // L + V
    if (HANGUL_L_BASE..HANGUL_L_BASE + HANGUL_L_COUNT).contains(&a)
        && (HANGUL_V_BASE..HANGUL_V_BASE + HANGUL_V_COUNT).contains(&b)
    {
        let l_index = a - HANGUL_L_BASE;
        let v_index = b - HANGUL_V_BASE;
        return Some(HANGUL_S_BASE + (l_index * HANGUL_V_COUNT + v_index) * HANGUL_T_COUNT);
    }
    // LV + T
    if (HANGUL_S_BASE..HANGUL_S_BASE + HANGUL_S_COUNT).contains(&a)
        && (a - HANGUL_S_BASE) % HANGUL_T_COUNT == 0
        && (HANGUL_T_BASE + 1..HANGUL_T_BASE + HANGUL_T_COUNT).contains(&b)
    {
        return Some(a + (b - HANGUL_T_BASE));
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// Full canonical decomposition
// ─────────────────────────────────────────────────────────────────────

fn decompose_one(cp: u32, out: &mut Vec<u32>) {
    if hangul_decompose(cp, out) {
        return;
    }
    if let Some(entry) = ucd_table().get(&cp) {
        if let Some(ref decomp) = entry.canonical_decomp {
            for &child in decomp {
                decompose_one(child, out);
            }
            return;
        }
    }
    out.push(cp);
}

fn canonical_decompose(input: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(input.len());
    for &cp in input {
        decompose_one(cp, &mut out);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────
// Canonical reordering (stable sort by CCC within non-starter runs)
// ─────────────────────────────────────────────────────────────────────

fn canonical_reorder(seq: &mut [u32]) {
    let n = seq.len();
    let mut i = 0;
    while i < n {
        if ccc(seq[i]) == 0 {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < n && ccc(seq[j]) != 0 {
            j += 1;
        }
        // Stable sort seq[i..j] by CCC.
        let mut run: Vec<u32> = seq[i..j].to_vec();
        run.sort_by_key(|&cp| ccc(cp));
        seq[i..j].copy_from_slice(&run);
        i = j;
    }
}

// ─────────────────────────────────────────────────────────────────────
// Canonical composition
// ─────────────────────────────────────────────────────────────────────

fn canonical_compose(seq: &[u32]) -> Vec<u32> {
    if seq.is_empty() {
        return Vec::new();
    }
    let comp = composition_table();
    let mut out: Vec<u32> = Vec::with_capacity(seq.len());
    let mut starter_idx: Option<usize> = None;
    let mut last_ccc: i32 = -1;

    for &cp in seq {
        let cp_ccc = ccc(cp);

        if let Some(si) = starter_idx {
            let starter = out[si];
            // Try hangul, then composition table.
            let composed =
                hangul_compose(starter, cp).or_else(|| comp.get(&(starter, cp)).copied());

            // Blocked check (UAX #15 D115): last_ccc != 0 means a combiner
            // is buffered between the active starter and this candidate. A
            // non-starter candidate is blocked when that buffered combiner
            // has CCC >= its own; a starter candidate (cp_ccc == 0) is
            // blocked outright by any buffered combiner.
            let blocked =
                last_ccc != 0 && (cp_ccc == 0 || last_ccc >= cp_ccc as i32);

            if !blocked {
                if let Some(c) = composed {
                    out[si] = c;
                    // last_ccc unchanged — we just merged a combiner
                    // into the starter (its CCC effectively absorbed).
                    continue;
                }
            }
        }

        out.push(cp);
        if cp_ccc == 0 {
            starter_idx = Some(out.len() - 1);
            last_ccc = 0;
        } else {
            last_ccc = cp_ccc as i32;
        }
    }

    out
}

pub fn to_nfc(input: &[u32]) -> Vec<u32> {
    let mut nfd = canonical_decompose(input);
    canonical_reorder(&mut nfd);
    canonical_compose(&nfd)
}

/// UAX #15 NFD — canonical decompose + canonical reorder, without
/// the recomposition pass.  Required by the UTS #39 §4 +§5.4
/// confusable-skeleton bracket.
pub fn to_nfd(input: &[u32]) -> Vec<u32> {
    let mut seq = canonical_decompose(input);
    canonical_reorder(&mut seq);
    seq
}

// ─────────────────────────────────────────────────────────────────────
// Full compatibility decomposition (NFKD/NFKC)
// ─────────────────────────────────────────────────────────────────────

/// Recursively decompose `cp` using its compatibility mapping when present,
/// otherwise its canonical mapping, otherwise Hangul algorithmic
/// decomposition — the full decomposition of UAX #15 for NFKD.
fn compat_decompose_one(cp: u32, out: &mut Vec<u32>) {
    if hangul_decompose(cp, out) {
        return;
    }
    if let Some(entry) = ucd_table().get(&cp) {
        if let Some(ref decomp) = entry.compat_decomp {
            for &child in decomp {
                compat_decompose_one(child, out);
            }
            return;
        }
        if let Some(ref decomp) = entry.canonical_decomp {
            for &child in decomp {
                compat_decompose_one(child, out);
            }
            return;
        }
    }
    out.push(cp);
}

fn compat_decompose(input: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(input.len());
    for &cp in input {
        compat_decompose_one(cp, &mut out);
    }
    out
}

/// UAX #15 NFKD — full compatibility decompose + canonical reorder.
pub fn to_nfkd(input: &[u32]) -> Vec<u32> {
    let mut seq = compat_decompose(input);
    canonical_reorder(&mut seq);
    seq
}

/// UAX #15 NFKC — NFKD followed by canonical recomposition.
pub fn to_nfkc(input: &[u32]) -> Vec<u32> {
    let nfkd = to_nfkd(input);
    canonical_compose(&nfkd)
}

// ─────────────────────────────────────────────────────────────────────
// CaseFolding.txt — default full case folding (RFC 8265 § 5.2.4)
// ─────────────────────────────────────────────────────────────────────

const CASE_FOLDING_RAW: &str = include_str!("../../../data/CaseFolding.txt");

fn parse_case_folding() -> HashMap<u32, Vec<u32>> {
    let mut out = HashMap::new();
    for line in CASE_FOLDING_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        let parts: Vec<&str> = stripped.split(';').map(str::trim).collect();
        if parts.len() < 3 {
            continue;
        }
        let status = parts[1];
        // UCD CaseFolding.txt: keep only status C (Common) and F (Full)
        // entries — the union RFC 8265 § 5.2.4 calls "default full case
        // folding".  Status S (Simple) is redundant with C/F, status T
        // is Turkic-locale-specific.
        if status != "C" && status != "F" {
            continue;
        }
        let src = match parse_hex(parts[0]) {
            Some(s) => s,
            None => continue,
        };
        let tgt: Vec<u32> = parts[2].split_whitespace().filter_map(parse_hex).collect();
        if tgt.is_empty() {
            continue;
        }
        out.insert(src, tgt);
    }
    out
}

fn case_folding_table() -> &'static HashMap<u32, Vec<u32>> {
    static T: OnceLock<HashMap<u32, Vec<u32>>> = OnceLock::new();
    T.get_or_init(parse_case_folding)
}

/// Default full case folding of a codepoint sequence per
/// RFC 8265 § 5.2.4 / UCD CaseFolding.txt status C ∪ F.
/// Codepoints absent from the table fold to themselves.
pub fn case_fold(input: &[u32]) -> Vec<u32> {
    let table = case_folding_table();
    let mut out = Vec::with_capacity(input.len());
    for &cp in input {
        match table.get(&cp) {
            Some(replacement) => out.extend_from_slice(replacement),
            None => out.push(cp),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────
// Scripts.txt — codepoint → primary script
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct RangeEntry<T> {
    start: u32,
    end: u32,
    value: T,
}

fn parse_range_field(s: &str) -> Option<(u32, u32)> {
    let s = s.trim();
    if let Some(idx) = s.find("..") {
        let a = parse_hex(&s[..idx])?;
        let b = parse_hex(&s[idx + 2..])?;
        Some((a, b))
    } else {
        let a = parse_hex(s)?;
        Some((a, a))
    }
}

fn parse_scripts() -> Vec<RangeEntry<String>> {
    let mut out = Vec::new();
    for line in SCRIPTS_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        let parts: Vec<&str> = stripped.splitn(2, ';').collect();
        if parts.len() < 2 {
            continue;
        }
        let (start, end) = match parse_range_field(parts[0]) {
            Some(r) => r,
            None => continue,
        };
        let value = parts[1].trim().to_string();
        out.push(RangeEntry { start, end, value });
    }
    out.sort_by_key(|r| r.start);
    out
}

fn scripts_table() -> &'static Vec<RangeEntry<String>> {
    static T: OnceLock<Vec<RangeEntry<String>>> = OnceLock::new();
    T.get_or_init(parse_scripts)
}

pub fn script_of(cp: u32) -> &'static str {
    let table = scripts_table();
    let idx = table.partition_point(|r| r.start <= cp);
    if idx > 0 {
        let entry = &table[idx - 1];
        if cp <= entry.end {
            return &entry.value;
        }
    }
    "Unknown"
}

// ─────────────────────────────────────────────────────────────────────
// ScriptExtensions.txt — codepoint → list of scripts (abbrev)
// ─────────────────────────────────────────────────────────────────────

fn parse_script_extensions() -> Vec<RangeEntry<Vec<String>>> {
    let mut out = Vec::new();
    for line in SCRIPT_EXTENSIONS_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        let parts: Vec<&str> = stripped.splitn(2, ';').collect();
        if parts.len() < 2 {
            continue;
        }
        let (start, end) = match parse_range_field(parts[0]) {
            Some(r) => r,
            None => continue,
        };
        let value: Vec<String> = parts[1]
            .trim()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if !value.is_empty() {
            out.push(RangeEntry { start, end, value });
        }
    }
    out.sort_by_key(|r| r.start);
    out
}

fn script_extensions_table() -> &'static Vec<RangeEntry<Vec<String>>> {
    static T: OnceLock<Vec<RangeEntry<Vec<String>>>> = OnceLock::new();
    T.get_or_init(parse_script_extensions)
}

/// The script abbreviations the resolver can name: exactly those that occur
/// in `ScriptExtensions.txt`.  `Unicode/ResolvedScripts.lean` models the same
/// set as the `ScriptAbbrev` enum, and its `scriptToAbbrev` is partial over
/// `Script` for that reason, so a script outside this set resolves to no
/// abbreviation on both sides.
fn script_extension_abbrevs() -> &'static std::collections::BTreeSet<String> {
    static T: OnceLock<std::collections::BTreeSet<String>> = OnceLock::new();
    T.get_or_init(|| {
        script_extensions_table()
            .iter()
            .flat_map(|row| row.value.iter().cloned())
            .collect()
    })
}

/// Resolve scripts for `cp`.  Returns the ScriptExtensions list
/// (which can be multiple abbreviations like "Adlm Arab Mand") if
/// the codepoint has one, otherwise the single primary script
/// from Scripts.txt.
///
/// A codepoint whose primary script has no abbreviation in the resolver's
/// vocabulary resolves to the empty set, mirroring
/// `Unicode/ResolvedScripts.lean`'s `resolveScripts`, whose fallback yields
/// `[]` when `scriptToAbbrev` is `none`.  Returning a singleton there instead
/// would make every unknown-script codepoint look Single-Script, which puts
/// `restrictionLevel` one rung too strict and hides `RestrictionLow`.
pub fn resolve_scripts(cp: u32) -> Vec<String> {
    let table = script_extensions_table();
    let idx = table.partition_point(|r| r.start <= cp);
    if idx > 0 {
        let entry = &table[idx - 1];
        if cp <= entry.end {
            return entry.value.clone();
        }
    }
    // Map full script name from Scripts.txt to its abbreviation.
    let primary = script_of(cp);
    let abbrev = script_long_to_abbrev(primary);
    if script_extension_abbrevs().contains(abbrev) {
        vec![abbrev.to_string()]
    } else {
        Vec::new()
    }
}

/// Authoritative long-name → 4-letter abbreviation table for the
/// Script property.  Parsed once from the bundled
/// `PropertyValueAliases.txt`.  Every long name that appears in
/// `Scripts.txt` for UCD 17.0.0 has a row here; an unknown name
/// surfacing in this function is a data-file integrity failure
/// rather than an expected case, so the lookup panics fail-fast
/// instead of silently falling through.
fn parse_script_name_to_abbrev() -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in PROPERTY_VALUE_ALIASES_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        let parts: Vec<&str> = stripped.split(';').map(str::trim).collect();
        if parts.len() < 3 {
            continue;
        }
        if parts[0] != "sc" {
            continue;
        }
        let short = parts[1].to_string();
        let long = parts[2].to_string();
        out.insert(long, short);
    }
    out
}

fn script_name_to_abbrev() -> &'static HashMap<String, String> {
    static T: OnceLock<HashMap<String, String>> = OnceLock::new();
    T.get_or_init(parse_script_name_to_abbrev)
}

fn script_long_to_abbrev(name: &str) -> &str {
    match script_name_to_abbrev().get(name) {
        Some(short) => short.as_str(),
        None => panic!(
            "script_long_to_abbrev: '{}' not in PropertyValueAliases.txt",
            name
        ),
    }
}

pub fn is_common_script(cp: u32) -> bool {
    let s = script_of(cp);
    s == "Common"
}

pub fn is_inherited_script(cp: u32) -> bool {
    let s = script_of(cp);
    s == "Inherited"
}

pub fn is_ignored_for_intersection(cp: u32) -> bool {
    is_common_script(cp) || is_inherited_script(cp)
}

/// The union of all resolved scripts across non-Common, non-Inherited
/// codepoints of `input`.  Counts every distinct script family that
/// appears in at least one codepoint's resolved-script set.
pub fn string_script_union(input: &[u32]) -> Vec<String> {
    let mut acc: Vec<String> = Vec::new();
    for &cp in input {
        if is_ignored_for_intersection(cp) {
            continue;
        }
        for s in resolve_scripts(cp) {
            if !acc.iter().any(|x| x == &s) {
                acc.push(s);
            }
        }
    }
    acc
}

// ─────────────────────────────────────────────────────────────────────
// IdentifierStatus.txt — UTS #39 General-Security-Profile Allowed set
// ─────────────────────────────────────────────────────────────────────

fn parse_identifier_status() -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for line in IDENTIFIER_STATUS_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        let parts: Vec<&str> = stripped.splitn(2, ';').collect();
        if parts.len() < 2 {
            continue;
        }
        let status = parts[1].trim();
        if status != "Allowed" {
            continue;
        }
        if let Some((start, end)) = parse_range_field(parts[0]) {
            out.push((start, end));
        }
    }
    out.sort_by_key(|r| r.0);
    out
}

fn identifier_allowed_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(parse_identifier_status)
}

pub fn is_id_allowed(cp: u32) -> bool {
    let table = identifier_allowed_ranges();
    let idx = table.partition_point(|r| r.0 <= cp);
    if idx > 0 {
        let entry = &table[idx - 1];
        if cp <= entry.1 {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────
// DerivedCoreProperties.txt — Default_Ignorable_Code_Point ranges
// ─────────────────────────────────────────────────────────────────────

fn parse_default_ignorable() -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for line in DERIVED_CORE_PROPERTIES_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        let parts: Vec<&str> = stripped.splitn(2, ';').collect();
        if parts.len() < 2 {
            continue;
        }
        if parts[1].trim() != "Default_Ignorable_Code_Point" {
            continue;
        }
        if let Some((start, end)) = parse_range_field(parts[0]) {
            out.push((start, end));
        }
    }
    out.sort_by_key(|r| r.0);
    out
}

fn default_ignorable_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(parse_default_ignorable)
}

/// True iff `cp` has the `Default_Ignorable_Code_Point` derived
/// property per UAX #44.  Includes the zero-width / format-control
/// characters (ZWSP, ZWNJ, ZWJ, WJ, BOM, soft hyphen, bidi
/// embedding controls, Mongolian / variation selectors, the tag
/// block, etc.) — codepoints that render as nothing and which an
/// attacker can insert into a target name without changing the
/// visible glyph stream.  Used by `letter_skeleton` in
/// homoglyph_confusable to close the invisible-insertion bypass.
pub fn is_default_ignorable(cp: u32) -> bool {
    let table = default_ignorable_ranges();
    let idx = table.partition_point(|r| r.0 <= cp);
    if idx > 0 {
        let entry = &table[idx - 1];
        if cp <= entry.1 {
            return true;
        }
    }
    false
}

/// True iff `cp` is a whitespace codepoint per UCD PropList.txt
/// `White_Space` property.  Includes ASCII tab/newline/space,
/// no-break space (U+00A0), narrow no-break space (U+202F —
/// frequently abused for invisibility-in-fonts), the
/// space-separator block U+2000..U+200A, line/paragraph
/// separators, medium math space (U+205F), and ideographic space
/// (U+3000).  Hardcoded since the table is small and stable.
///
/// Used by `letter_skeleton` to strip whitespace from typosquat
/// comparison — whitespace inside an identifier is universally
/// attacker abuse, never legitimate.
pub fn is_white_space(cp: u32) -> bool {
    matches!(cp,
        0x0009..=0x000D
      | 0x0020
      | 0x0085
      | 0x00A0
      | 0x1680
      | 0x2000..=0x200A
      | 0x2028..=0x2029
      | 0x202F
      | 0x205F
      | 0x3000
    )
}

// ─────────────────────────────────────────────────────────────────────
// UTS #39 § 5.1 Restriction-level classification
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestrictionLevel {
    AsciiOnly,
    SingleScript,
    HighlyRestrictive,
    ModeratelyRestrictive,
    MinimallyRestrictive,
    Unrestricted,
}

pub fn is_ascii_only(cps: &[u32]) -> bool {
    cps.iter().all(|&cp| cp < 0x80)
}

fn intersect_many(sets: &[Vec<String>]) -> Vec<String> {
    if sets.is_empty() {
        return Vec::new();
    }
    let mut acc = sets[0].clone();
    for s in &sets[1..] {
        acc.retain(|x| s.contains(x));
    }
    acc
}

pub fn string_resolved_scripts(cps: &[u32]) -> Vec<String> {
    let non_ignored: Vec<u32> = cps
        .iter()
        .copied()
        .filter(|&cp| !is_ignored_for_intersection(cp))
        .collect();
    if non_ignored.is_empty() {
        return Vec::new();
    }
    let sets: Vec<Vec<String>> = non_ignored.iter().map(|&cp| resolve_scripts(cp)).collect();
    intersect_many(&sets)
}

pub fn is_single_script(cps: &[u32]) -> bool {
    !is_ascii_only(cps) && !string_resolved_scripts(cps).is_empty()
}

fn covered_japanese() -> Vec<&'static str> {
    vec!["Latn", "Hani", "Hira", "Kana"]
}
fn covered_chinese() -> Vec<&'static str> {
    vec!["Latn", "Hani", "Bopo"]
}
fn covered_korean() -> Vec<&'static str> {
    vec!["Latn", "Hani", "Hang"]
}

fn intersects(a: &[String], b: &[&str]) -> bool {
    a.iter().any(|x| b.contains(&x.as_str()))
}

fn all_within_covered(cps: &[u32], covered: &[&str]) -> bool {
    cps.iter().all(|&cp| {
        if is_ignored_for_intersection(cp) {
            return true;
        }
        let r = resolve_scripts(cp);
        !r.is_empty() && intersects(&r, covered)
    })
}

pub fn is_covered_cjk(cps: &[u32]) -> bool {
    all_within_covered(cps, &covered_japanese())
        || all_within_covered(cps, &covered_chinese())
        || all_within_covered(cps, &covered_korean())
}

pub fn is_highly_restrictive(cps: &[u32]) -> bool {
    is_single_script(cps) || is_covered_cjk(cps)
}

pub fn is_moderately_restrictive_shape(cps: &[u32]) -> bool {
    let mut other: Option<String> = None;
    for &cp in cps {
        if is_ignored_for_intersection(cp) {
            continue;
        }
        let r = resolve_scripts(cp);
        if r.is_empty() {
            return false;
        }
        if r.iter().any(|s| s == "Latn") {
            continue;
        }
        let s = r[0].clone();
        if s == "Cyrl" || s == "Grek" {
            return false;
        }
        match &other {
            None => other = Some(s),
            Some(o) => {
                if &s != o {
                    return false;
                }
            }
        }
    }
    other.is_some()
}

pub fn is_minimally_restrictive(cps: &[u32]) -> bool {
    cps.iter().all(|&cp| is_id_allowed(cp))
}

pub fn restriction_level(cps: &[u32]) -> RestrictionLevel {
    if is_ascii_only(cps) {
        RestrictionLevel::AsciiOnly
    } else if is_single_script(cps) {
        RestrictionLevel::SingleScript
    } else if is_highly_restrictive(cps) {
        RestrictionLevel::HighlyRestrictive
    } else if is_moderately_restrictive_shape(cps) {
        RestrictionLevel::ModeratelyRestrictive
    } else if is_minimally_restrictive(cps) {
        RestrictionLevel::MinimallyRestrictive
    } else {
        RestrictionLevel::Unrestricted
    }
}

#[cfg(test)]
mod nfkc_nfkd_tests {
    use super::{to_nfc, to_nfkc, to_nfkd};

    #[test]
    fn nfkc_known_vectors() {
        // ﬁ ligature (U+FB01) → "fi"
        assert_eq!(to_nfkc(&[0xFB01]), vec![0x66, 0x69]);
        // ① circled digit one (U+2460) → "1"
        assert_eq!(to_nfkc(&[0x2460]), vec![0x31]);
        // Fullwidth A (U+FF21) → "A"
        assert_eq!(to_nfkc(&[0xFF21]), vec![0x41]);
        // Precomposed é (U+00E9) stays é under NFKC.
        assert_eq!(to_nfkc(&[0x00E9]), vec![0x00E9]);
        // Decomposed e + combining acute → é under NFKC.
        assert_eq!(to_nfkc(&[0x0065, 0x0301]), vec![0x00E9]);
        // Hangul jamo L+V+T → precomposed syllable 한 (U+D55C).
        assert_eq!(to_nfkc(&[0x1112, 0x1161, 0x11AB]), vec![0xD55C]);
        // Plain ASCII unchanged.
        assert_eq!(to_nfkc(&[0x48, 0x69]), vec![0x48, 0x69]);
    }

    #[test]
    fn nfkd_known_vectors() {
        // Fullwidth A → "A" (compatibility decomposition, no recomposition).
        assert_eq!(to_nfkd(&[0xFF21]), vec![0x41]);
        // ﬁ → "fi".
        assert_eq!(to_nfkd(&[0xFB01]), vec![0x66, 0x69]);
        // Precomposed é → e + combining acute under NFKD.
        assert_eq!(to_nfkd(&[0x00E9]), vec![0x0065, 0x0301]);
    }

    #[test]
    fn compose_blocking_d115() {
        // UAX #15 D115 blocking, matching the Lean spec
        // `Unicode.Normalization.Compose.stepCompose`: a starter candidate
        // is blocked from the active starter by any buffered non-starter
        // between them. Hangul L + combining grave (CCC 230) + Hangul V —
        // the grave stands between L and V, so L+V must NOT compose to
        // U+AC00 across it.
        assert_eq!(
            to_nfc(&[0x1100, 0x0300, 0x1161]),
            vec![0x1100, 0x0300, 0x1161]
        );
        // The same jamo without the intervening mark compose normally.
        assert_eq!(to_nfc(&[0x1100, 0x1161]), vec![0xAC00]);
        assert_eq!(to_nfc(&[0x1100, 0x1161, 0x11A8]), vec![0xAC01]);
        // A + combining-below (CCC 220) + combining-grave (CCC 230): the
        // grave has the higher CCC, so it is not blocked and composes with
        // A to À, while the lower-CCC below-mark remains buffered.
        assert_eq!(to_nfc(&[0x0041, 0x0316, 0x0300]), vec![0x00C0, 0x0316]);
    }
}

// ─────────────────────────────────────────────────────────────────────
// UAX #21 case mapping (to_lower) from SpecialCasing.txt + UnicodeData
// simple lowercase (field 13), mirroring Unicode.Casing. Keystone for
// bip39-canonical's default-locale canonicalisation.
// ─────────────────────────────────────────────────────────────────────

const SPECIAL_CASING_RAW: &str = include_str!("../../../data/SpecialCasing.txt");

/// The locales `SpecialCasing.txt` distinguishes. `Default` covers everything
/// not tagged Turkish / Azeri / Lithuanian.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    /// Everything not tagged tr / az / lt.
    Default,
    /// Turkish (`tr`).
    Turkish,
    /// Azeri (`az`).
    Azeri,
    /// Lithuanian (`lt`).
    Lithuanian,
}

struct CasingRow {
    lower: Vec<u32>,
    upper: Vec<u32>,
    conditions: Vec<String>,
}

fn parse_codepoint_list(field: &str) -> Vec<u32> {
    field.split_whitespace().filter_map(parse_hex).collect()
}

fn parse_special_casing() -> HashMap<u32, Vec<CasingRow>> {
    let mut rows: HashMap<u32, Vec<CasingRow>> = HashMap::new();
    for line in SPECIAL_CASING_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        let fields: Vec<&str> = stripped.split(';').map(|f| f.trim()).collect();
        if fields.len() < 4 {
            continue;
        }
        let code = match parse_hex(fields[0]) {
            Some(cp) => cp,
            None => continue,
        };
        let conditions: Vec<String> = if fields.len() > 4 && !fields[4].is_empty() {
            fields[4].split_whitespace().map(|t| t.to_string()).collect()
        } else {
            Vec::new()
        };
        rows.entry(code).or_default().push(CasingRow {
            lower: parse_codepoint_list(fields[1]),
            upper: parse_codepoint_list(fields[3]),
            conditions,
        });
    }
    rows
}

fn special_casing_rows() -> &'static HashMap<u32, Vec<CasingRow>> {
    static T: OnceLock<HashMap<u32, Vec<CasingRow>>> = OnceLock::new();
    T.get_or_init(parse_special_casing)
}

fn parse_simple_lowercase() -> HashMap<u32, u32> {
    let mut lower = HashMap::new();
    for line in UNICODE_DATA_RAW.lines() {
        let fields: Vec<&str> = line.split(';').collect();
        if fields.len() < 15 {
            continue;
        }
        if let (Some(cp), false) = (parse_hex(fields[0]), fields[13].is_empty()) {
            if let Some(l) = parse_hex(fields[13]) {
                lower.insert(cp, l);
            }
        }
    }
    lower
}

fn simple_lowercase_table() -> &'static HashMap<u32, u32> {
    static T: OnceLock<HashMap<u32, u32>> = OnceLock::new();
    T.get_or_init(parse_simple_lowercase)
}

fn simple_lowercase(cp: u32) -> u32 {
    *simple_lowercase_table().get(&cp).unwrap_or(&cp)
}

fn parse_simple_uppercase() -> HashMap<u32, u32> {
    let mut upper = HashMap::new();
    for line in UNICODE_DATA_RAW.lines() {
        let fields: Vec<&str> = line.split(';').collect();
        if fields.len() < 15 {
            continue;
        }
        if let (Some(cp), false) = (parse_hex(fields[0]), fields[12].is_empty()) {
            if let Some(u) = parse_hex(fields[12]) {
                upper.insert(cp, u);
            }
        }
    }
    upper
}

fn simple_uppercase_table() -> &'static HashMap<u32, u32> {
    static T: OnceLock<HashMap<u32, u32>> = OnceLock::new();
    T.get_or_init(parse_simple_uppercase)
}

fn simple_uppercase(cp: u32) -> u32 {
    *simple_uppercase_table().get(&cp).unwrap_or(&cp)
}

fn parse_casing_property(name: &str) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for line in DERIVED_CORE_PROPERTIES_RAW.lines() {
        let stripped = strip_comment_and_trim(line);
        if stripped.is_empty() {
            continue;
        }
        let parts: Vec<&str> = stripped.splitn(2, ';').collect();
        if parts.len() < 2 || parts[1].trim() != name {
            continue;
        }
        if let Some(range) = parse_range_field(parts[0]) {
            out.push(range);
        }
    }
    out
}

fn cased_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(|| parse_casing_property("Cased"))
}

fn soft_dotted_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(|| parse_casing_property("Soft_Dotted"))
}

fn in_ranges(ranges: &[(u32, u32)], cp: u32) -> bool {
    ranges.iter().any(|&(lo, hi)| lo <= cp && cp <= hi)
}

fn is_cased(cp: u32) -> bool {
    in_ranges(cased_ranges(), cp)
}

fn is_soft_dotted(cp: u32) -> bool {
    in_ranges(soft_dotted_ranges(), cp)
}

// UAX #31 default identifier + UTS #39 whole-string admissibility, mirroring
// Unicode.Identifier. XID_Start / XID_Continue come from DerivedCoreProperties;
// `is_id_allowed` (above) is the per-codepoint UTS #39 Identifier_Status test.

fn xid_start_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(|| parse_casing_property("XID_Start"))
}

fn xid_continue_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(|| parse_casing_property("XID_Continue"))
}

fn is_xid_start(cp: u32) -> bool {
    in_ranges(xid_start_ranges(), cp)
}

fn is_xid_continue(cp: u32) -> bool {
    in_ranges(xid_continue_ranges(), cp)
}

/// UAX #31 default identifier start: `XID_Start` or `U+005F LOW LINE`.
fn is_default_id_start(cp: u32) -> bool {
    is_xid_start(cp) || cp == 0x005F
}

/// UAX #31 default identifier continue: `XID_Continue`.
fn is_default_id_continue(cp: u32) -> bool {
    is_xid_continue(cp)
}

/// True iff `cps` is a well-formed UAX #31 default identifier: a non-empty
/// sequence whose first codepoint is a default-id start and whose remaining
/// codepoints are default-id continues.
pub fn is_default_identifier(cps: &[u32]) -> bool {
    match cps.split_first() {
        None => false,
        Some((first, rest)) => is_default_id_start(*first) && rest.iter().all(|&cp| is_default_id_continue(cp)),
    }
}

/// True iff `cps` is a well-formed default identifier AND every codepoint has
/// `Identifier_Status = Allowed` per UTS #39 (the whole-string admissibility
/// predicate `isAllowedIdentifier`).
pub fn is_allowed_identifier(cps: &[u32]) -> bool {
    is_default_identifier(cps) && cps.iter().all(|&cp| is_id_allowed(cp))
}

// Context predicates (UAX #21). `rev_prefix` is the preceding codepoints
// nearest-first; `suffix` the strictly-following ones.

fn more_above_after(suffix: &[u32]) -> bool {
    for &cp in suffix {
        let c = ccc(cp);
        if c == 230 {
            return true;
        }
        if c == 0 {
            return false;
        }
    }
    false
}

fn after_soft_dotted(rev_prefix: &[u32]) -> bool {
    for &cp in rev_prefix {
        if is_soft_dotted(cp) {
            return true;
        }
        let c = ccc(cp);
        if c == 0 || c == 230 {
            return false;
        }
    }
    false
}

fn after_i(rev_prefix: &[u32]) -> bool {
    for &cp in rev_prefix {
        if cp == 0x0049 {
            return true;
        }
        let c = ccc(cp);
        if c == 0 || c == 230 {
            return false;
        }
    }
    false
}

fn before_dot(suffix: &[u32]) -> bool {
    for &cp in suffix {
        if cp == 0x0307 {
            return true;
        }
        if ccc(cp) == 0 {
            return false;
        }
    }
    false
}

fn has_cased_before(rev_prefix: &[u32]) -> bool {
    for &cp in rev_prefix {
        if is_cased(cp) {
            return true;
        }
        if ccc(cp) == 0 {
            return false;
        }
    }
    false
}

fn has_cased_after(suffix: &[u32]) -> bool {
    for &cp in suffix {
        if is_cased(cp) {
            return true;
        }
        if ccc(cp) == 0 {
            return false;
        }
    }
    false
}

fn final_sigma(rev_prefix: &[u32], suffix: &[u32]) -> bool {
    has_cased_before(rev_prefix) && !has_cased_after(suffix)
}

fn is_locale_condition(condition: &str) -> bool {
    condition == "tr" || condition == "az" || condition == "lt"
}

fn locale_matches(locale: Locale, conditions: &[String]) -> bool {
    if !conditions.iter().any(|c| is_locale_condition(c)) {
        return true;
    }
    conditions.iter().any(|c| {
        (c == "tr" && locale == Locale::Turkish)
            || (c == "az" && locale == Locale::Azeri)
            || (c == "lt" && locale == Locale::Lithuanian)
    })
}

fn conditions_hold(
    locale: Locale,
    rev_prefix: &[u32],
    suffix: &[u32],
    conditions: &[String],
) -> bool {
    if !locale_matches(locale, conditions) {
        return false;
    }
    for c in conditions {
        if is_locale_condition(c) {
            continue;
        }
        let ok = match c.as_str() {
            "Final_Sigma" => final_sigma(rev_prefix, suffix),
            "Not_Final_Sigma" => !final_sigma(rev_prefix, suffix),
            "After_Soft_Dotted" => after_soft_dotted(rev_prefix),
            "More_Above" => more_above_after(suffix),
            "Not_Before_Dot" => !before_dot(suffix),
            "After_I" => after_i(rev_prefix),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn find_special_row(
    locale: Locale,
    rev_prefix: &[u32],
    suffix: &[u32],
    cp: u32,
) -> Option<&'static CasingRow> {
    let candidates = special_casing_rows().get(&cp)?;
    for row in candidates {
        if !row.conditions.is_empty() && conditions_hold(locale, rev_prefix, suffix, &row.conditions)
        {
            return Some(row);
        }
    }
    candidates.iter().find(|row| row.conditions.is_empty())
}

/// Lowercase a single codepoint in its full input context (UAX #21): the
/// SpecialCasing row whose conditions hold, else the simple lowercase mapping.
/// `rev_prefix` is the preceding codepoints nearest-first; `suffix` the
/// strictly-following ones. Exposed so context-sensitive detectors (e.g.
/// locale-case-inversion) can compare per-position mappings across locales.
pub fn lower_codepoint(locale: Locale, rev_prefix: &[u32], suffix: &[u32], cp: u32) -> Vec<u32> {
    match find_special_row(locale, rev_prefix, suffix, cp) {
        Some(row) => row.lower.clone(),
        None => vec![simple_lowercase(cp)],
    }
}

/// Uppercase a single codepoint in its full input context (UAX #21): the
/// SpecialCasing row whose conditions hold (its uppercase column), else the
/// simple uppercase mapping. `rev_prefix` is the preceding codepoints
/// nearest-first; `suffix` the strictly-following ones. Exposed so
/// context-sensitive detectors (e.g. case-expansion-mismatch) can measure the
/// case-mapped length per position.
pub fn upper_codepoint(locale: Locale, rev_prefix: &[u32], suffix: &[u32], cp: u32) -> Vec<u32> {
    match find_special_row(locale, rev_prefix, suffix, cp) {
        Some(row) => row.upper.clone(),
        None => vec![simple_uppercase(cp)],
    }
}

/// Lowercase a codepoint sequence under `locale` (UAX #21 full case mapping):
/// SpecialCasing rows where their conditions hold, else the simple lowercase
/// mapping. Computed from the pinned UCD tables, not the runtime.
pub fn to_lower(locale: Locale, cps: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut rev_prefix: Vec<u32> = Vec::new();
    for (index, &cp) in cps.iter().enumerate() {
        let suffix = &cps[index + 1..];
        out.extend_from_slice(&lower_codepoint(locale, &rev_prefix, suffix, cp));
        rev_prefix.insert(0, cp);
    }
    out
}

#[cfg(test)]
mod casing_tests {
    use super::{to_lower, Locale};

    #[test]
    fn to_lower_spot_checks() {
        // Ground truth: the Unicode.Casing spot-check theorems.
        assert_eq!(
            to_lower(Locale::Default, &[0x48, 0x65, 0x6C, 0x6C, 0x6F]),
            vec![0x68, 0x65, 0x6C, 0x6C, 0x6F]
        );
        assert_eq!(to_lower(Locale::Default, &[0x0049]), vec![0x0069]);
        assert_eq!(to_lower(Locale::Turkish, &[0x0049]), vec![0x0131]);
        assert_eq!(to_lower(Locale::Azeri, &[0x0049]), vec![0x0131]);
        assert_eq!(to_lower(Locale::Turkish, &[0x0130]), vec![0x0069]);
        assert_eq!(to_lower(Locale::Default, &[0x0130]), vec![0x0069, 0x0307]);
    }
}
