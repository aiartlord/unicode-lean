%% width-class-confusion — detection of UAX #11 East Asian Width class
%% confusion. A Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint whose
%% NFKD form carries a different EAW class is a compatibility-fold homograph:
%%
%%     U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
%%     U+FF11 '１' (F)  ->  U+0031 '1' (Na)
%%     U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)
%%
%% The two-system bypass this detects: a validator that whitelists ASCII
%% rejects `Ａ', while a downstream NFKC step at storage or comparison time
%% folds it to plain `A'. The attacker claims the username ADMIN with ＡＤＭＩＮ
%% against a system that did not normalise before whitelisting.
%%
%% Distinct from renderer divergence's FullwidthVariance, which fires on
%% F-class codepoints for renderer-cohort reasons; this is the NFKC-fold
%% verdict, and the two can fire on one input independently.
%%
%% Detection is per input position and uses NFKD, because every compatibility
%% decomposition path goes through it: the EAW class of the input codepoint is
%% compared against the EAW class of the first NFKD output codepoint. Hangul
%% syllables decompose to jamos that are still W class, so pure Hangul stays
%% clear. The East Asian Width table is read from the port's own bundled
%% `EastAsianWidth.txt' via `usec_ucd:east_asian_width', never a host library.
%%
%% Direct port of `Unicode/Security/Form/WidthClassConfusion.lean'.
%%
%% Sub-threats, in the priority order `detect/1' applies:
%%   `{fullwidth_fold, Pos}' — a Fullwidth codepoint folding to another class.
%%   `{halfwidth_fold, Pos}' — reached only when no Fullwidth fold fires first.

-module(usec_width_class_confusion).

-export([detect/1, sub_threat_tag/1, classify_tag/1, classify_positions/1,
         is_clear/1]).

%% ─────────────────────────────────────────────────────────────────────
%% §1 Per-position width-fold scan
%% ─────────────────────────────────────────────────────────────────────

%% True iff the NFKD head of `Cp' carries a different EAW class.
has_width_fold(Cp) ->
    case usec_ucd:to_nfkd([Cp]) of
        [] -> false;
        [Head | _] ->
            usec_ucd:east_asian_width(Head) =/= usec_ucd:east_asian_width(Cp)
    end.

%% First zero-based position whose codepoint has class `Want' and folds away.
first_fold(Input, Want) ->
    first_fold(Input, Want, 0).

first_fold([], _Want, _Index) ->
    none;
first_fold([Cp | Rest], Want, Index) ->
    case usec_ucd:east_asian_width(Cp) =:= Want andalso has_width_fold(Cp) of
        true -> {ok, Index};
        false -> first_fold(Rest, Want, Index + 1)
    end.

fold_count(Input, Want) ->
    length([Cp || Cp <- Input,
                  usec_ucd:east_asian_width(Cp) =:= Want,
                  has_width_fold(Cp)]).

%% ─────────────────────────────────────────────────────────────────────
%% §2 Detection
%% ─────────────────────────────────────────────────────────────────────

%% A Fullwidth fold takes priority over a Halfwidth one, matching the
%% reference's sub-threat order.
detect(Input) ->
    Classification =
        case first_fold(Input, f) of
            {ok, Pos} -> {hazard, {fullwidth_fold, Pos}, [Pos]};
            none ->
                case first_fold(Input, h) of
                    {ok, Pos} -> {hazard, {halfwidth_fold, Pos}, [Pos]};
                    none -> clear
                end
        end,
    #{input => Input,
      classify => Classification,
      fullwidth_fold_count => fold_count(Input, f),
      halfwidth_fold_count => fold_count(Input, h)}.

%% ─────────────────────────────────────────────────────────────────────
%% §3 Projection helpers
%% ─────────────────────────────────────────────────────────────────────

sub_threat_tag({fullwidth_fold, _Pos}) -> <<"FullwidthFold">>;
sub_threat_tag({halfwidth_fold, _Pos}) -> <<"HalfwidthFold">>.

is_clear(clear) -> true;
is_clear({hazard, _Sub, _Positions}) -> false.

classify_tag(clear) -> undefined;
classify_tag({hazard, Sub, _Positions}) -> sub_threat_tag(Sub).

classify_positions(clear) -> [];
classify_positions({hazard, _Sub, Positions}) -> Positions.
