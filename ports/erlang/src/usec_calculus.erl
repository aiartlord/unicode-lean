%%% Shared verdict vocabulary for the Security Conformance Layer, mirroring
%%% `unicode_python.security.calculus` / `Unicode.Security.Calculus`.
%%%
%%% Detector families are atoms; the enumeration order below is the order
%%% in which the aggregator walks them and the priority order callers rely
%%% on when composing verdicts across modules.  `Severity` is an ordered
%%% integer vocabulary; `ClassificationKind` distinguishes the verdict kind
%%% independent of any family-specific sub-threat payload.
-module(usec_calculus).

-export([families/0, severity_value/1, default_severity/1]).

-export_type([family/0, severity/0, classification_kind/0, adversary_tier/0]).

-type family() ::
        malformed_utf8 | malformed_utf16 | malformed_utf32
      | tag_block_payload | variation_selector_payload | zero_width_payload
      | surrogate_reassembly | bidi_control_balance | noncharacter_control
      | homoglyph_confusable | mixed_script_admissibility | emoji_zwj_integrity
      | skin_tone_variation_forgery | source_display_divergence
      | filename_disguise | rtl_injection | renderer_divergence
      | normalization_bomb | stream_safe_violation | locale_case_inversion
      | case_expansion_mismatch | width_class_confusion | nfc_idempotence_witness
      | identifier_form_drift | covert_display_compound | confusable_bidi_compound
      | admissibility_form_drift | bip39_canonical | hash_input_stability
      | ai_watermark_detectability.

-type severity() :: informational | low | moderate | high | critical.

-type classification_kind() :: clear | hazard | compound | informational.

-type adversary_tier() :: a0 | a1 | a2 | a3 | a4.

%% @doc The detector families, in aggregator/priority order.
-spec families() -> [family()].
families() ->
    [malformed_utf8, malformed_utf16, malformed_utf32,
     tag_block_payload, variation_selector_payload, zero_width_payload,
     surrogate_reassembly, bidi_control_balance, noncharacter_control,
     homoglyph_confusable, mixed_script_admissibility, emoji_zwj_integrity,
     skin_tone_variation_forgery, source_display_divergence,
     filename_disguise, rtl_injection, renderer_divergence,
     normalization_bomb, stream_safe_violation, locale_case_inversion,
     case_expansion_mismatch, width_class_confusion, nfc_idempotence_witness,
     identifier_form_drift, covert_display_compound, confusable_bidi_compound,
     admissibility_form_drift, bip39_canonical, hash_input_stability,
     ai_watermark_detectability].

%% @doc The ordered severity level as an integer:
%% informational < low < moderate < high < critical.
-spec severity_value(severity()) -> 0..4.
severity_value(informational) -> 0;
severity_value(low) -> 1;
severity_value(moderate) -> 2;
severity_value(high) -> 3;
severity_value(critical) -> 4.

%% @doc The default severity associated with each classification kind.
-spec default_severity(classification_kind()) -> severity().
default_severity(clear) -> informational;
default_severity(hazard) -> moderate;
default_severity(compound) -> high;
default_severity(informational) -> informational.
