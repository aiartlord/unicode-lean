//! hash-input-stability (K2) — detection of inputs that are not in canonical
//! hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input
//! hashed by a signer must be byte-identical to the input hashed by the
//! verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
//! policy, line-ending convention) the resulting hashes diverge silently while
//! both sides believe they signed the same content.
//!
//! Direct port of `Unicode/Security/Crypto/HashInputStability.lean`. The
//! canonical (hash-stable) form is `trim_trailing(to_nfc(input))`, where
//! `trim_trailing` strips only ASCII whitespace {U+0020, U+0009, U+000A,
//! U+000D}; Unicode whitespace (U+00A0, U+2000..U+200A, U+3000) is content and
//! is not stripped. NFC is the port's `ucd::to_nfc`, never a host normalizer.
//!
//! Six probes run in strict priority order (first hit wins):
//!
//!   1. `encodingMismatch`         (context: `declared_encoding`)
//!   2. `webhookSignatureDrift`    (context: `server_bytes`)
//!   3. `auditLogReinterpretation` (context: `as_written`)
//!   4. `signedMessageRule`        (context: `rfc_rule`)
//!   5. `trailingWhitespace`       (bare input)
//!   6. `normalizationDrift`       (bare input)
//!   7. clear
//!
//! Context-specific probes fire first because they carry more precise threat
//! information than the generic probes. `detect` is the convenience wrapper
//! `detect_with_context(&Context::default(), input)` that leaves the four
//! context-bearing probes silent.

use crate::security::identity::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/// RFC canonicalisation profiles that the `signedMessageRule` probe checks
/// against. Each variant names a specific canonicalisation rule from a
/// published RFC; callers pass one as `Context::rfc_rule` to opt the probe in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfcRule {
    /// RFC 4880 §5.2.4 — detached signatures normalise trailing whitespace;
    /// trailing whitespace in the body causes signature mismatch.
    Pgp4880TrailingWhitespace,
    /// RFC 9580 (current OpenPGP) — line-endings normalise to CRLF before
    /// signing; a bare LF or bare CR violates the canonicalisation rule.
    Pgp9580LineEnding,
    /// RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires strings to be in
    /// NFC before serialisation.
    Rfc8785NfcRequirement,
    /// RFC 8259 §7 — JSON strings must escape control characters
    /// (U+0000..U+001F); unescaped control bytes in a string violate.
    Rfc8259ControlChar,
    /// RFC 7515 §2 — JWS Base64URL encoding; any character outside
    /// `[A-Za-z0-9_-]` is a canonicalisation violation.
    Rfc7515JwsBase64Url,
    /// RFC 6376 §3.4.4 — DKIM relaxed body canonicalization collapses internal
    /// whitespace runs to a single SP; a multi-char internal whitespace run
    /// indicates the canonicalisation has not been applied.
    Rfc6376DkimRelaxed,
    /// RFC 5751 §3.1.1 — S/MIME canonical text; like PGP 9580, a bare LF or
    /// bare CR (not part of a CRLF pair) violates.
    Rfc5751SmimeLineEnding,
}

impl RfcRule {
    /// Fixture-string identifier for an `RfcRule` — used by the conformance
    /// harness's attribution parser to round-trip rule selections.
    pub fn tag(self) -> &'static str {
        match self {
            RfcRule::Pgp4880TrailingWhitespace => "pgp4880TrailingWhitespace",
            RfcRule::Pgp9580LineEnding => "pgp9580LineEnding",
            RfcRule::Rfc8785NfcRequirement => "rfc8785NfcRequirement",
            RfcRule::Rfc8259ControlChar => "rfc8259ControlChar",
            RfcRule::Rfc7515JwsBase64Url => "rfc7515JwsBase64Url",
            RfcRule::Rfc6376DkimRelaxed => "rfc6376DkimRelaxed",
            RfcRule::Rfc5751SmimeLineEnding => "rfc5751SmimeLineEnding",
        }
    }

    /// Inverse of `tag`. Returns `None` for unrecognised strings.
    pub fn from_tag(tag: &str) -> Option<RfcRule> {
        match tag {
            "pgp4880TrailingWhitespace" => Some(RfcRule::Pgp4880TrailingWhitespace),
            "pgp9580LineEnding" => Some(RfcRule::Pgp9580LineEnding),
            "rfc8785NfcRequirement" => Some(RfcRule::Rfc8785NfcRequirement),
            "rfc8259ControlChar" => Some(RfcRule::Rfc8259ControlChar),
            "rfc7515JwsBase64Url" => Some(RfcRule::Rfc7515JwsBase64Url),
            "rfc6376DkimRelaxed" => Some(RfcRule::Rfc6376DkimRelaxed),
            "rfc5751SmimeLineEnding" => Some(RfcRule::Rfc5751SmimeLineEnding),
            _unrecognised => None,
        }
    }
}

/// Sub-threats this detector can fire. Two probes fire from the raw input
/// alone (`TrailingWhitespace`, `NormalizationDrift`); the other four require
/// the corresponding `Context` field to be set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// Input diverges from its NFC form; `first_divergent_pos` is the first
    /// diverging codepoint index.
    NormalizationDrift {
        /// First codepoint index at which the input diverges from its NFC form.
        first_divergent_pos: usize,
    },
    /// Input has trailing ASCII whitespace; `count` is how many codepoints.
    TrailingWhitespace {
        /// Number of trailing ASCII-whitespace codepoints stripped by the trim.
        count: usize,
    },
    /// Declared encoding disagrees with the codepoint array (or the array holds
    /// an invalid scalar).
    EncodingMismatch {
        /// The encoding label the caller declared.
        declared_enc: String,
        /// The encoding detected from the codepoint array ("utf-8" or "invalid").
        detected_enc: String,
    },
    /// Input violates the named RFC's canonicalisation rule at `first_pos`.
    SignedMessageRule {
        /// Fixture tag of the violated `RfcRule`.
        rfc_rule: String,
        /// First position at which the RFC rule is violated.
        first_pos: usize,
    },
    /// The re-read `input` differs from `Context::as_written` at
    /// `first_divergent_pos`.
    AuditLogReinterpretation {
        /// First position at which the re-read input differs from the written form.
        first_divergent_pos: usize,
    },
    /// The client `input` differs from `Context::server_bytes` at `first_pos`.
    WebhookSignatureDrift {
        /// First position at which the client input differs from the server bytes.
        first_pos: usize,
    },
}

impl SubThreat {
    /// Human-facing classification tag for this sub-threat.
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::NormalizationDrift { first_divergent_pos: _ } => "NormalizationDrift",
            SubThreat::TrailingWhitespace { count: _ } => "TrailingWhitespace",
            SubThreat::EncodingMismatch {
                declared_enc: _,
                detected_enc: _,
            } => "EncodingMismatch",
            SubThreat::SignedMessageRule {
                rfc_rule: _,
                first_pos: _,
            } => "SignedMessageRule",
            SubThreat::AuditLogReinterpretation { first_divergent_pos: _ } => {
                "AuditLogReinterpretation"
            }
            SubThreat::WebhookSignatureDrift { first_pos: _ } => "WebhookSignatureDrift",
        }
    }
}

/// Context passed to `detect_with_context` to enable the four context-bearing
/// probes. Each field is `None` by default — the empty context is the identity
/// case: `detect_with_context(&Context::default(), input)` equals
/// `detect(input)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// The encoding label the caller claims their input is in. When set and not
    /// (case-insensitively) UTF-8, fires `encodingMismatch` immediately.
    pub declared_encoding: Option<String>,
    /// The RFC canonicalisation rule the caller is operating under. When set,
    /// scans `input` for violations and fires `signedMessageRule`.
    pub rfc_rule: Option<RfcRule>,
    /// The original "as-written" form of an audit-log entry whose re-read is
    /// `input`. When set, fires `auditLogReinterpretation` on first divergence.
    pub as_written: Option<Vec<u32>>,
    /// The server-side recomputed bytes for a webhook signature. When set,
    /// fires `webhookSignatureDrift` on first divergence against `input`.
    pub server_bytes: Option<Vec<u32>>,
}

/// Top-level K2 classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// The input is already hash-stable under every enabled probe.
    Clear,
    /// A hazard was found: the sub-threat and its implicated positions.
    Hazard {
        /// The sub-threat that fired.
        sub: SubThreat,
        /// The codepoint positions the sub-threat implicates.
        positions: Vec<usize>,
    },
}

impl Classification {
    /// True iff the input is clear.
    pub fn is_clear(&self) -> bool {
        match self {
            Classification::Clear => true,
            Classification::Hazard { sub: _, positions: _ } => false,
        }
    }

    /// Human-facing tag for a hazard, or `None` when clear.
    pub fn tag(&self) -> Option<&'static str> {
        match self {
            Classification::Clear => None,
            Classification::Hazard { sub, positions: _ } => Some(sub.tag()),
        }
    }

    /// Implicated positions ( empty when clear ).
    pub fn positions(&self) -> &[usize] {
        match self {
            Classification::Clear => &[],
            Classification::Hazard { sub: _, positions } => positions,
        }
    }
}

/// K2 verdict — the structured output of `detect`. `stable_size` is the
/// codepoint count of the hash-stable canonical form; downstream callers
/// compare it against `input.len()` to size the byte-drift their hash sees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The scanned input codepoints.
    pub input: Vec<u32>,
    /// The classification verdict.
    pub classify: Classification,
    /// The hash-stable canonical form of the input.
    pub stable_form: Vec<u32>,
    /// Codepoint count of `stable_form`.
    pub stable_size: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §3 Canonicalisation pipeline
// ─────────────────────────────────────────────────────────────────────

/// True iff `cp` is an ASCII whitespace codepoint that line-oriented
/// hash-input protocols treat as framing rather than content: U+0020 SPACE,
/// U+0009 TAB, U+000A LF, U+000D CR.
fn is_ascii_whitespace(cp: u32) -> bool {
    cp == 0x0020 || cp == 0x0009 || cp == 0x000A || cp == 0x000D
}

/// Count of trailing ASCII whitespace codepoints in `input`.
fn count_trailing_whitespace(input: &[u32]) -> usize {
    input
        .iter()
        .rev()
        .take_while(|&&cp| is_ascii_whitespace(cp))
        .count()
}

/// Strip trailing ASCII whitespace.
fn trim_trailing(input: &[u32]) -> Vec<u32> {
    let keep = input.len() - count_trailing_whitespace(input);
    input[..keep].to_vec()
}

/// The K2 hash-stable form of an input: NFC then trim, in spec order.
pub fn hash_stable(input: &[u32]) -> Vec<u32> {
    trim_trailing(&ucd::to_nfc(input))
}

// ─────────────────────────────────────────────────────────────────────
// §5 Priority position-finder
// ─────────────────────────────────────────────────────────────────────

/// First position at which `a` and `b` diverge, or the length of the shared
/// prefix when one strictly extends the other. `None` when identical.
fn first_array_divergence(a: &[u32], b: &[u32]) -> Option<usize> {
    let common = a.len().min(b.len());
    for i in 0..common {
        if a[i] != b[i] {
            return Some(i);
        }
    }
    if a.len() != b.len() {
        return Some(common);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// §6 Context-bearing probes
// ─────────────────────────────────────────────────────────────────────

/// Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
fn ascii_lower(cp: u32) -> u32 {
    if (0x41..=0x5A).contains(&cp) {
        cp + 0x20
    } else {
        cp
    }
}

/// True iff `label` (after ASCII case-fold) names UTF-8: accepts "utf-8",
/// "UTF-8", "UTF8", "utf8". Non-ASCII characters pass through unchanged.
fn is_utf8_label(label: &str) -> bool {
    let normalised: String = label
        .chars()
        .map(|c| match char::from_u32(ascii_lower(c as u32)) {
            Some(lowered) => lowered,
            None => c,
        })
        .collect();
    normalised == "utf-8" || normalised == "utf8"
}

/// True iff `cp` is a valid Unicode scalar value: in `[0, 0x10FFFF]` and not a
/// surrogate `[0xD800, 0xDFFF]`.
fn is_valid_scalar(cp: u32) -> bool {
    cp <= 0x10FFFF && !(0xD800..=0xDFFF).contains(&cp)
}

/// First position in `input` holding a codepoint that is not a valid Unicode
/// scalar, or `None` if every codepoint is valid.
fn first_invalid_scalar(input: &[u32]) -> Option<usize> {
    input
        .iter()
        .position(|&cp| !is_valid_scalar(cp))
}

/// Probe: `encodingMismatch`. Validity is dispatched first — an invalid scalar
/// fires with `detected_enc = "invalid"` regardless of the declared label;
/// otherwise a non-UTF-8 label fires with `detected_enc = "utf-8"` at
/// position 0. Returns `(declared, detected, first_pos)` when firing.
fn encoding_mismatch_probe(declared: &str, input: &[u32]) -> Option<(String, String, usize)> {
    match first_invalid_scalar(input) {
        Some(pos) => Some((declared.to_string(), "invalid".to_string(), pos)),
        None => {
            if is_utf8_label(declared) {
                None
            } else {
                Some((declared.to_string(), "utf-8".to_string(), 0))
            }
        }
    }
}

/// Probe: `signedMessageRule` for `pgp4880TrailingWhitespace`. Same condition
/// as `trailingWhitespace`; returns the first position of the trailing run.
fn pgp4880_violation(input: &[u32]) -> Option<usize> {
    let trailing = count_trailing_whitespace(input);
    if trailing > 0 {
        Some(input.len() - trailing)
    } else {
        None
    }
}

/// Probe: `signedMessageRule` for `pgp9580LineEnding`. First bare LF (U+000A
/// not preceded by CR) or bare CR (U+000D not followed by LF).
fn pgp9580_violation(input: &[u32]) -> Option<usize> {
    for (i, &cp) in input.iter().enumerate() {
        if cp == 0x000A {
            // LF: violating iff not preceded by CR.
            let preceded_by_cr = i > 0 && input[i - 1] == 0x000D;
            if !preceded_by_cr {
                return Some(i);
            }
        } else if cp == 0x000D {
            // CR: violating iff not followed by LF.
            let followed_by_lf = i + 1 < input.len() && input[i + 1] == 0x000A;
            if !followed_by_lf {
                return Some(i);
            }
        }
    }
    None
}

/// Probe: `signedMessageRule` for `rfc8785NfcRequirement`. Same condition as
/// `normalizationDrift`; returns the first NFC divergence position.
fn rfc8785_violation(input: &[u32]) -> Option<usize> {
    let nfc = ucd::to_nfc(input);
    if input == nfc.as_slice() {
        None
    } else {
        first_array_divergence(input, &nfc)
    }
}

/// Probe: `signedMessageRule` for `rfc8259ControlChar`. First C0 control
/// (U+0000..U+001F) — the JSON-permitted whitespace still requires escaping,
/// so it also counts.
fn rfc8259_violation(input: &[u32]) -> Option<usize> {
    input.iter().position(|&cp| cp <= 0x1F)
}

/// True iff `cp` is in the JWS Base64URL alphabet `[A-Za-z0-9_-]`.
fn is_base64_url(cp: u32) -> bool {
    (0x41..=0x5A).contains(&cp)      // A-Z
        || (0x61..=0x7A).contains(&cp) // a-z
        || (0x30..=0x39).contains(&cp) // 0-9
        || cp == 0x2D                  // '-'
        || cp == 0x5F // LOW LINE
}

/// Probe: `signedMessageRule` for `rfc7515JwsBase64Url`. First codepoint
/// outside `[A-Za-z0-9_-]`.
fn rfc7515_violation(input: &[u32]) -> Option<usize> {
    input.iter().position(|&cp| !is_base64_url(cp))
}

/// True iff `cp` is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
fn is_dkim_whitespace(cp: u32) -> bool {
    cp == 0x20 || cp == 0x09
}

/// Probe: `signedMessageRule` for `rfc6376DkimRelaxed`. Position of the second
/// whitespace codepoint in the first internal whitespace run longer than one.
fn rfc6376_violation(input: &[u32]) -> Option<usize> {
    for (i, &cp) in input.iter().enumerate() {
        if is_dkim_whitespace(cp) && i > 0 && is_dkim_whitespace(input[i - 1]) {
            return Some(i);
        }
    }
    None
}

/// Probe: `signedMessageRule` for `rfc5751SmimeLineEnding`. Reuses the PGP 9580
/// bare-line-ending rule.
fn rfc5751_violation(input: &[u32]) -> Option<usize> {
    pgp9580_violation(input)
}

/// Dispatch the RFC-rule probe. First violation position, or `None` if clean.
fn rfc_rule_violation(rule: RfcRule, input: &[u32]) -> Option<usize> {
    match rule {
        RfcRule::Pgp4880TrailingWhitespace => pgp4880_violation(input),
        RfcRule::Pgp9580LineEnding => pgp9580_violation(input),
        RfcRule::Rfc8785NfcRequirement => rfc8785_violation(input),
        RfcRule::Rfc8259ControlChar => rfc8259_violation(input),
        RfcRule::Rfc7515JwsBase64Url => rfc7515_violation(input),
        RfcRule::Rfc6376DkimRelaxed => rfc6376_violation(input),
        RfcRule::Rfc5751SmimeLineEnding => rfc5751_violation(input),
    }
}

// ─────────────────────────────────────────────────────────────────────
// §7 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The full K2 detection function. Runs all six probes in priority order,
/// with the context-bearing probes ahead of the generic ones.
pub fn detect_with_context(ctx: &Context, input: &[u32]) -> Verdict {
    let stable = hash_stable(input);

    // Probe 1: encodingMismatch.
    let encoding_hit: Option<(String, String, usize)> = match &ctx.declared_encoding {
        Some(label) => encoding_mismatch_probe(label, input),
        None => None,
    };

    // Probe 2: webhookSignatureDrift.
    let webhook_hit: Option<usize> = match &ctx.server_bytes {
        Some(server) => first_array_divergence(input, server),
        None => None,
    };

    // Probe 3: auditLogReinterpretation.
    let audit_hit: Option<usize> = match &ctx.as_written {
        Some(written) => first_array_divergence(written, input),
        None => None,
    };

    // Probe 4: signedMessageRule.
    let rfc_hit: Option<(RfcRule, usize)> = match ctx.rfc_rule {
        Some(rule) => rfc_rule_violation(rule, input).map(|pos| (rule, pos)),
        None => None,
    };

    // Probe 5: trailingWhitespace.
    let trailing_count = count_trailing_whitespace(input);

    // Probe 6: normalizationDrift.
    let nfc = ucd::to_nfc(input);
    let non_nfc_pos = if input == nfc.as_slice() {
        None
    } else {
        first_array_divergence(input, &nfc)
    };

    let classification = classify(
        encoding_hit,
        webhook_hit,
        audit_hit,
        rfc_hit,
        trailing_count,
        input.len(),
        non_nfc_pos,
    );

    Verdict {
        stable_size: stable.len(),
        stable_form: stable,
        classify: classification,
        input: input.to_vec(),
    }
}

/// The priority resolver: first hit wins, in the spec's fixed order.
#[allow(clippy::too_many_arguments)]
fn classify(
    encoding_hit: Option<(String, String, usize)>,
    webhook_hit: Option<usize>,
    audit_hit: Option<usize>,
    rfc_hit: Option<(RfcRule, usize)>,
    trailing_count: usize,
    input_len: usize,
    non_nfc_pos: Option<usize>,
) -> Classification {
    if let Some((declared, detected, pos)) = encoding_hit {
        return Classification::Hazard {
            sub: SubThreat::EncodingMismatch {
                declared_enc: declared,
                detected_enc: detected,
            },
            positions: vec![pos],
        };
    }
    if let Some(pos) = webhook_hit {
        return Classification::Hazard {
            sub: SubThreat::WebhookSignatureDrift { first_pos: pos },
            positions: vec![pos],
        };
    }
    if let Some(pos) = audit_hit {
        return Classification::Hazard {
            sub: SubThreat::AuditLogReinterpretation {
                first_divergent_pos: pos,
            },
            positions: vec![pos],
        };
    }
    if let Some((rule, pos)) = rfc_hit {
        return Classification::Hazard {
            sub: SubThreat::SignedMessageRule {
                rfc_rule: rule.tag().to_string(),
                first_pos: pos,
            },
            positions: vec![pos],
        };
    }
    if trailing_count > 0 {
        let p = input_len - trailing_count;
        return Classification::Hazard {
            sub: SubThreat::TrailingWhitespace {
                count: trailing_count,
            },
            positions: vec![p],
        };
    }
    match non_nfc_pos {
        Some(p) => Classification::Hazard {
            sub: SubThreat::NormalizationDrift {
                first_divergent_pos: p,
            },
            positions: vec![p],
        },
        None => Classification::Clear,
    }
}

/// Convenience wrapper over `detect_with_context` with the empty context —
/// equivalent to running only the two bare-input probes (`trailingWhitespace`,
/// `normalizationDrift`).
pub fn detect(input: &[u32]) -> Verdict {
    detect_with_context(&Context::default(), input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth: every `stable_*`, `detect_*`, and priority theorem in
    // `Unicode/Security/Crypto/HashInputStability.lean`. Each Lean theorem
    // maps to one `#[test]` below; a theorem asserting multiple conjuncts maps
    // to one assertion per conjunct.
    //
    // ── Context-bearing probe vectors (for the port fan-out to transcribe;
    //    the shared detector-fixture schema cannot express a Context, so these
    //    live only here). Format: rfc_rule / declared_encoding / as_written /
    //    server_bytes → expected tag & positions.
    //
    //   declared_encoding = Some("utf-16"),  [0x61,0x62,0x63]      → EncodingMismatch, [0]
    //   declared_encoding = Some("utf-8"),   [0x61,0xD800,0x62]    → EncodingMismatch, [1]  (invalid surrogate)
    //   declared_encoding = Some("utf-8"),   [0x61,0x110000,0x62]  → EncodingMismatch, [1]  (out of range)
    //   declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"), [0x61,0x62,0x63] → clear
    //   rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20]          → SignedMessageRule, [1]
    //   rfc_rule = Pgp9580LineEnding, [0x61,0x0A,0x62]             → SignedMessageRule, [1]  (bare LF)
    //   rfc_rule = Pgp9580LineEnding, [0x61,0x62,0x63,0x0D,0x0A,0x64,0x65,0x66] → clear (CRLF)
    //   rfc_rule = Rfc8785NfcRequirement, [0x0065,0x0301]          → SignedMessageRule, [0]
    //   rfc_rule = Rfc8259ControlChar, [0x61,0x01,0x62]            → SignedMessageRule, [1]
    //   rfc_rule = Rfc7515JwsBase64Url, [0x41,0x2B,0x42]           → SignedMessageRule, [1]  ('+')
    //   rfc_rule = Rfc7515JwsBase64Url, [0x41,0x61,0x30,0x2D,0x5F,0x7A,0x5A,0x39] → clear
    //   rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62]       → SignedMessageRule, [2]
    //   rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x62]            → clear (single space)
    //   rfc_rule = Rfc5751SmimeLineEnding, [0x61,0x0A,0x62]        → SignedMessageRule, [1]  (bare LF)
    //   as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x64] → AuditLogReinterpretation, [2]
    //   as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
    //   server_bytes = Some([0x61,0x62,0x64]), input [0x61,0x62,0x63] → WebhookSignatureDrift, [2]
    //   server_bytes = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
    //   declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
    //     [0x0065,0x0301,0x0A]                                     → EncodingMismatch  (priority over rfc)
    //   server_bytes = Some([0x61,0x62,0x65]) + as_written = Some([0x61,0x62,0x66]),
    //     input [0x61,0x62,0x63]                                   → WebhookSignatureDrift (priority over audit)
    //   rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20]          → SignedMessageRule (priority over trailing)

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    fn ctx_tag(ctx: &Context, input: &[u32]) -> Option<&'static str> {
        detect_with_context(ctx, input).classify.tag()
    }

    // ── §4 hash_stable spot checks ──────────────────────────────────────

    #[test]
    fn stable_empty() {
        assert_eq!(hash_stable(&[]), Vec::<u32>::new());
    }

    #[test]
    fn stable_ascii_idempotent() {
        assert_eq!(hash_stable(&[0x61, 0x62, 0x63]), vec![0x61, 0x62, 0x63]);
        assert_eq!(
            hash_stable(&hash_stable(&[0x61, 0x62, 0x63])),
            hash_stable(&[0x61, 0x62, 0x63])
        );
    }

    #[test]
    fn stable_strips_trailing_space() {
        assert_eq!(hash_stable(&[0x61, 0x20]), vec![0x61]);
    }

    #[test]
    fn stable_strips_trailing_tab() {
        assert_eq!(hash_stable(&[0x61, 0x09]), vec![0x61]);
    }

    #[test]
    fn stable_strips_trailing_lf() {
        assert_eq!(hash_stable(&[0x61, 0x0A]), vec![0x61]);
    }

    #[test]
    fn stable_strips_trailing_crlf() {
        assert_eq!(hash_stable(&[0x61, 0x0D, 0x0A]), vec![0x61]);
    }

    #[test]
    fn stable_preserves_internal_space() {
        assert_eq!(hash_stable(&[0x61, 0x20, 0x62]), vec![0x61, 0x20, 0x62]);
    }

    #[test]
    fn stable_composes_nfc() {
        assert_eq!(hash_stable(&[0x0065, 0x0301]), vec![0x00E9]);
    }

    #[test]
    fn stable_preserves_trailing_nbsp() {
        assert_eq!(hash_stable(&[0x61, 0x00A0]), vec![0x61, 0x00A0]);
    }

    // ── §8 detect spot checks ───────────────────────────────────────────

    #[test]
    fn detect_empty_clear() {
        assert_eq!(detect(&[]).classify, Classification::Clear);
    }

    #[test]
    fn detect_ascii_idempotent() {
        assert_eq!(
            detect(&[0x61, 0x62, 0x63]).classify,
            Classification::Clear
        );
    }

    #[test]
    fn detect_trailing_space() {
        let v = detect(&[0x61, 0x20]);
        assert_eq!(v.classify.tag(), Some("TrailingWhitespace"));
        assert_eq!(v.stable_size, 1);
        assert_eq!(v.classify.positions(), &[1]);
    }

    #[test]
    fn detect_trailing_crlf() {
        let v = detect(&[0x61, 0x0D, 0x0A]);
        assert_eq!(v.classify.tag(), Some("TrailingWhitespace"));
        assert_eq!(v.stable_size, 1);
    }

    #[test]
    fn detect_decomposed_e_acute() {
        let v = detect(&[0x0065, 0x0301]);
        assert_eq!(v.classify.tag(), Some("NormalizationDrift"));
        assert_eq!(v.classify.positions(), &[0]);
    }

    #[test]
    fn detect_precomposed_e_acute_clear() {
        assert_eq!(detect(&[0x00E9]).classify, Classification::Clear);
    }

    #[test]
    fn detect_priority_trailing_over_nfc() {
        // Decomposed "é " — TrailingWhitespace wins over NormalizationDrift.
        assert_eq!(tag(&[0x0065, 0x0301, 0x20]), Some("TrailingWhitespace"));
    }

    #[test]
    fn detect_internal_space_clear() {
        assert_eq!(detect(&[0x61, 0x20, 0x62]).classify, Classification::Clear);
    }

    // ── §9 context-bearing probe spot checks ────────────────────────────

    #[test]
    fn detect_with_context_default_matches_detect() {
        let d = detect(&[0x61, 0x62, 0x63]);
        let c = detect_with_context(&Context::default(), &[0x61, 0x62, 0x63]);
        assert_eq!(c.classify, d.classify);
        assert_eq!(c.stable_size, d.stable_size);
    }

    #[test]
    fn detect_encoding_mismatch_utf16_label() {
        let ctx = Context {
            declared_encoding: Some("utf-16".to_string()),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x61, 0x62, 0x63]);
        assert_eq!(v.classify.tag(), Some("EncodingMismatch"));
        assert_eq!(v.classify.positions(), &[0]);
    }

    #[test]
    fn detect_encoding_invalid_surrogate() {
        let ctx = Context {
            declared_encoding: Some("utf-8".to_string()),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x61, 0xD800, 0x62]);
        assert_eq!(v.classify.tag(), Some("EncodingMismatch"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    #[test]
    fn detect_encoding_invalid_out_of_range() {
        let ctx = Context {
            declared_encoding: Some("utf-8".to_string()),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x61, 0x110000, 0x62]);
        assert_eq!(v.classify.tag(), Some("EncodingMismatch"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    #[test]
    fn detect_encoding_utf8_label_case_insensitive() {
        for label in ["UTF-8", "utf-8", "UTF8", "utf8"] {
            let ctx = Context {
                declared_encoding: Some(label.to_string()),
                ..Context::default()
            };
            assert_eq!(
                detect_with_context(&ctx, &[0x61, 0x62, 0x63]).classify,
                Classification::Clear,
                "label {label} should be recognised as UTF-8"
            );
        }
    }

    #[test]
    fn detect_signed_message_pgp4880() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Pgp4880TrailingWhitespace),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x61, 0x20]);
        assert_eq!(v.classify.tag(), Some("SignedMessageRule"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    #[test]
    fn detect_signed_message_pgp9580_bare_lf() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Pgp9580LineEnding),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x61, 0x0A, 0x62]);
        assert_eq!(v.classify.tag(), Some("SignedMessageRule"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    #[test]
    fn detect_signed_message_pgp9580_crlf_clear_internal() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Pgp9580LineEnding),
            ..Context::default()
        };
        // "abc" CRLF "def".
        assert_eq!(
            ctx_tag(&ctx, &[0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66]),
            None
        );
    }

    #[test]
    fn detect_signed_message_rfc8785_decomposed() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Rfc8785NfcRequirement),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x0065, 0x0301]);
        assert_eq!(v.classify.tag(), Some("SignedMessageRule"));
        assert_eq!(v.classify.positions(), &[0]);
    }

    #[test]
    fn detect_signed_message_rfc8259_control() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Rfc8259ControlChar),
            ..Context::default()
        };
        // "a" + U+0001 + "b".
        let v = detect_with_context(&ctx, &[0x61, 0x01, 0x62]);
        assert_eq!(v.classify.tag(), Some("SignedMessageRule"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    #[test]
    fn detect_signed_message_rfc7515_plus_char() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Rfc7515JwsBase64Url),
            ..Context::default()
        };
        // '+' (0x2B) is standard Base64 but not Base64URL.
        let v = detect_with_context(&ctx, &[0x41, 0x2B, 0x42]);
        assert_eq!(v.classify.tag(), Some("SignedMessageRule"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    #[test]
    fn detect_signed_message_rfc7515_clean_clear() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Rfc7515JwsBase64Url),
            ..Context::default()
        };
        // "Aa0-_zZ9".
        assert_eq!(
            ctx_tag(&ctx, &[0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39]),
            None
        );
    }

    #[test]
    fn detect_signed_message_rfc6376_double_space() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Rfc6376DkimRelaxed),
            ..Context::default()
        };
        // "a" + SP + SP + "b".
        let v = detect_with_context(&ctx, &[0x61, 0x20, 0x20, 0x62]);
        assert_eq!(v.classify.tag(), Some("SignedMessageRule"));
        assert_eq!(v.classify.positions(), &[2]);
    }

    #[test]
    fn detect_signed_message_rfc6376_single_space_clear() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Rfc6376DkimRelaxed),
            ..Context::default()
        };
        assert_eq!(ctx_tag(&ctx, &[0x61, 0x20, 0x62]), None);
    }

    #[test]
    fn detect_signed_message_rfc5751_bare_lf() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Rfc5751SmimeLineEnding),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x61, 0x0A, 0x62]);
        assert_eq!(v.classify.tag(), Some("SignedMessageRule"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    #[test]
    fn detect_audit_log_divergence() {
        let ctx = Context {
            as_written: Some(vec![0x61, 0x62, 0x63]),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x61, 0x62, 0x64]);
        assert_eq!(v.classify.tag(), Some("AuditLogReinterpretation"));
        assert_eq!(v.classify.positions(), &[2]);
    }

    #[test]
    fn detect_audit_log_identical_clear() {
        let ctx = Context {
            as_written: Some(vec![0x61, 0x62, 0x63]),
            ..Context::default()
        };
        assert_eq!(ctx_tag(&ctx, &[0x61, 0x62, 0x63]), None);
    }

    #[test]
    fn detect_webhook_signature_drift() {
        let ctx = Context {
            server_bytes: Some(vec![0x61, 0x62, 0x64]),
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &[0x61, 0x62, 0x63]);
        assert_eq!(v.classify.tag(), Some("WebhookSignatureDrift"));
        assert_eq!(v.classify.positions(), &[2]);
    }

    #[test]
    fn detect_webhook_signature_match_clear() {
        let ctx = Context {
            server_bytes: Some(vec![0x61, 0x62, 0x63]),
            ..Context::default()
        };
        assert_eq!(ctx_tag(&ctx, &[0x61, 0x62, 0x63]), None);
    }

    #[test]
    fn detect_priority_encoding_over_rfc() {
        let ctx = Context {
            declared_encoding: Some("utf-16".to_string()),
            rfc_rule: Some(RfcRule::Pgp9580LineEnding),
            ..Context::default()
        };
        // Bare LF (pgp9580) + decomposed é (rfc8785) labeled utf-16.
        assert_eq!(ctx_tag(&ctx, &[0x0065, 0x0301, 0x0A]), Some("EncodingMismatch"));
    }

    #[test]
    fn detect_priority_webhook_over_audit() {
        let ctx = Context {
            server_bytes: Some(vec![0x61, 0x62, 0x65]),
            as_written: Some(vec![0x61, 0x62, 0x66]),
            ..Context::default()
        };
        assert_eq!(
            ctx_tag(&ctx, &[0x61, 0x62, 0x63]),
            Some("WebhookSignatureDrift")
        );
    }

    #[test]
    fn detect_priority_rfc_over_trailing() {
        let ctx = Context {
            rfc_rule: Some(RfcRule::Pgp4880TrailingWhitespace),
            ..Context::default()
        };
        assert_eq!(ctx_tag(&ctx, &[0x61, 0x20]), Some("SignedMessageRule"));
    }

    // ── Round-trip of the RfcRule fixture tags ──────────────────────────

    #[test]
    fn rfc_rule_tag_roundtrip() {
        for rule in [
            RfcRule::Pgp4880TrailingWhitespace,
            RfcRule::Pgp9580LineEnding,
            RfcRule::Rfc8785NfcRequirement,
            RfcRule::Rfc8259ControlChar,
            RfcRule::Rfc7515JwsBase64Url,
            RfcRule::Rfc6376DkimRelaxed,
            RfcRule::Rfc5751SmimeLineEnding,
        ] {
            assert_eq!(RfcRule::from_tag(rule.tag()), Some(rule));
        }
        assert_eq!(RfcRule::from_tag("nope"), None);
    }
}
