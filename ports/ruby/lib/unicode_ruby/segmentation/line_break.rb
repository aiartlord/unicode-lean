# frozen_string_literal: true

require_relative "line_break_tables"
require_relative "grapheme"

# UAX #14 default line breaking.
#
# A port of the Lean algorithm Unicode.Segmentation.LineBreak.lineBreaks, whose
# lineBreaks_length theorem fixes the output shape: one break-opportunity flag
# per boundary position.  The rule order, rule bodies, and snapshot fields below
# mirror that reference — LB2 through LB31 in UAX #14 R7's canonical order,
# first match winning, the trailing LB31 breaking every otherwise-unmatched
# pair.
#
# Where a line may break is a property of a sequence rather than of a code
# point, so the entry point returns a flag per boundary instead of a predicate
# over code points.
#
# Three mechanisms carry the context the rules read:
#
# * LB1 is applied at lookup time by +resolved_class+, which folds the
#   tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet.  SA
#   needs General_Category to choose between CM and AL.
# * LB9 — treat X CM* / X ZWJ* as X — is realised through Snapshot, whose
#   fields hold the most recent class that was not CM or ZWJ.  LB10, treating a
#   leftover CM or ZWJ as AL, is the fallback taken when no such class exists.
# * The rules naming a third character — LB15b, LB15c, the LB25 bracket and the
#   fourth LB28a sub-rule — read forward from the position being decided.
#
# Two departures from the Lean.  Its positional reads are +lits[i]!+ and
# +cps[i]!+, panicking accessors; here every read goes through +Array#[]+, which
# yields +nil+ past the end, so no access can leave the sequence.  And its
# spSinceNoSp snapshot field is written by its fold and read by no rule, so this
# port omits it.
#
# The two properties UAX #14 needs beyond the Line_Break class —
# General_Category for LB1's SA resolution, the Pi/Pf quote refinement and
# LB30b, and East_Asian_Width for LB19a, LB25 and LB30 — come from the generated
# tables in +LineBreakTables+, so this module takes code points and needs no
# data directory, as +Grapheme+ does.

module UnicodeRuby
  module Segmentation
    # UAX #14 default line breaking over a code point sequence.
    module LineBreak
      module_function

      # ── Property lookups ──────────────────────────────────────────────────

      # The one range of a sorted, coalesced table covering +cp+, or nil.
      # The ranges partition the code space, so the covering range is unique.
      def lookup_range(table, cp)
        lo = 0
        hi = table.length
        while lo < hi
          mid = lo + ((hi - lo) / 2)
          first, last, value = table[mid]
          if cp < first
            hi = mid
          elsif cp > last
            lo = mid + 1
          else
            return value
          end
        end
        nil
      end

      # Raw Line_Break class of +cp+, before LB1.  A code point no range covers
      # is +:xx+, the default LineBreak.txt's own @missing header declares.
      def raw_class(cp)
        lookup_range(LineBreakTables::LB_RANGES, cp) || :xx
      end

      # General_Category of +cp+, +:cn+ when no range covers it.
      def general_category(cp)
        lookup_range(LineBreakTables::GC_RANGES, cp) || :cn
      end

      # East_Asian_Width of +cp+, +:n+ when the file omits it.
      def east_asian_width_class(cp)
        lookup_range(LineBreakTables::EAW_RANGES, cp) || :n
      end

      # ── LB1, the tailoring applied at lookup ──────────────────────────────

      # The Line_Break class +cp+ carries once LB1 has tailored it.
      #
      # AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
      # non-spacing or spacing combining mark and to AL otherwise.  Every other
      # class is already in the working alphabet.
      #
      # Memoized: the corpus asks for the same few hundred code points tens of
      # thousands of times, and each miss costs three binary searches.
      def resolved_class(cp)
        @resolved_cache ||= {}
        cached = @resolved_cache[cp]
        return cached unless cached.nil?

        @resolved_cache[cp] = compute_resolved_class(cp)
      end

      def compute_resolved_class(cp)
        case raw_class(cp)
        when :ai, :sg, :xx then :al
        when :cj then :ns
        when :sa
          # LB1 reads only the two combining-mark categories here; an enclosing
          # mark is not among them.
          gc = general_category(cp)
          gc == :mn || gc == :mc ? :cm : :al
        else raw_class(cp)
        end
      end

      # ── Class sets the rules name ─────────────────────────────────────────

      # Classes LB9 absorbs into the character before them.
      CM_ZWJ = [:cm, :zwj].freeze

      # Classes that block LB9's absorption, so a following CM or ZWJ stands on
      # its own and LB10 reads it as AL.
      BLOCKS_ABSORB = [:bk, :cr, :lf, :nl, :sp, :zw].freeze

      # The left context in which LB15a opens its initial-punctuation window:
      # an initial quote standing outside a word.
      PI_WINDOW_OPENERS = [:bk, :cr, :lf, :nl, :op, :qu, :gl, :sp, :zw].freeze

      # Classes that keep an open LB25 numeric chain open.
      NU_CHAIN_EXTENDERS = [:sy, :is, :cl, :cp, :pr].freeze

      # Classes that cannot open a line, so an LB15b final quote before one
      # closes rather than breaks.
      QUOTE_CLOSERS = [
        :sp, :gl, :wj, :cl, :qu, :cp, :ex, :is, :sy, :bk, :cr, :lf, :nl, :zw
      ].freeze

      # The start-of-segment set LB20.1 and LB20a require of a hyphen's own
      # left context.
      HYPHEN_LEFT_OPENERS = [:bk, :cr, :lf, :nl, :sp, :zw, :cb, :gl].freeze

      # East_Asian_Width values LB25 and LB30 exclude.
      EAST_ASIAN_FULL_WIDE = [:f, :w, :h].freeze

      # The wider set LB19a's tailoring treats as East Asian, Ambiguous
      # included.
      EAST_ASIAN_OR_AMBIGUOUS = [:f, :w, :h, :a].freeze

      # Classes carrying a mandatory break, which LB6 forbids breaking before.
      MANDATORY = [:bk, :cr, :lf, :nl].freeze

      # Hangul syllable classes, for LB26 and LB27.
      HANGUL = [:jl, :jv, :jt, :h2, :h3].freeze

      # U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
      DOTTED_CIRCLE = 0x25CC

      # U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0
      # moved it from class HY to class HH.
      HYPHEN = 0x2010

      # Whether LB9 absorbs this class into the character before it.
      def cm_zwj?(cls)
        CM_ZWJ.include?(cls)
      end

      # Whether the class is QU and the code point is initial punctuation, the
      # refinement LB15a reads.
      def pi_quote?(cp, cls)
        cls == :qu && general_category(cp) == :pi
      end

      # Whether the class is QU and the code point is final punctuation, the
      # refinement LB15b reads.
      def pf_quote?(cp, cls)
        cls == :qu && general_category(cp) == :pf
      end

      # Whether +cp+ is East_Asian_Width F, W or H, the set LB25 and LB30 read.
      def east_asian_full_wide?(cp)
        EAST_ASIAN_FULL_WIDE.include?(east_asian_width_class(cp))
      end

      # Whether +cp+ counts as East Asian for LB19a's tailoring.
      def east_asian_or_ambiguous?(cp)
        EAST_ASIAN_OR_AMBIGUOUS.include?(east_asian_width_class(cp))
      end

      # Whether the effective class is present and among +classes+.
      def eff_in?(effective, classes)
        !effective.nil? && classes.include?(effective)
      end

      # ── The left-hand context a boundary decision reads ───────────────────

      # The classes and code points of the most recent characters LB9 did not
      # absorb, plus the running counters the rules keep.  Mirrors the Lean
      # EffSnapshot.
      #
      # +eff_prev+ is the class of the most recent character that was not CM or
      # ZWJ and +eff_prev_cp+ its code point, which LB20a, LB21a and LB28a name
      # directly.  +eff_prev_no_sp+ skips SP as well.  +eff_prev_prev+ and
      # +eff_prev_prev_cp+ are the second most recent such character.
      # +in_pi_quote_window+ records an open LB15a window, +ri_run+ the length
      # of the current regional-indicator run for LB30a, and +in_nu_chain+ an
      # open LB25 numeric chain.
      Snapshot = Struct.new(
        :eff_prev, :eff_prev_cp, :eff_prev_no_sp, :eff_prev_prev,
        :eff_prev_prev_cp, :in_pi_quote_window, :ri_run, :in_nu_chain
      ) do
        # The context before any character has been read.
        def self.initial
          new(nil, nil, nil, nil, nil, false, 0, false)
        end
      end

      # The class a CM or ZWJ takes from what it attaches to under LB9, or AL
      # under LB10 when nothing absorbs it.
      def effective_class(cls, eff_prev)
        return cls unless cm_zwj?(cls)
        return :al if eff_prev.nil?

        BLOCKS_ABSORB.include?(eff_prev) ? :al : cls
      end

      # Fold one character into the context.  A character LB9 absorbs leaves the
      # context untouched, which is what makes the neighbours it records
      # effective rather than literal.  Mirrors the Lean buildSnapshots step.
      def advance(s, cp, cls)
        effective = effective_class(cls, s.eff_prev)
        return s if cm_zwj?(effective)

        # LB15a opens its window only where an initial-punctuation quote stands
        # outside a word; a space carries an open window forward.
        left_context_opens =
          s.eff_prev.nil? || PI_WINDOW_OPENERS.include?(s.eff_prev)
        in_pi_quote_window =
          if pi_quote?(cp, effective) && left_context_opens
            true
          elsif effective == :sp
            s.in_pi_quote_window
          else
            false
          end

        in_nu_chain =
          if effective == :nu
            true
          elsif s.in_nu_chain
            NU_CHAIN_EXTENDERS.include?(effective)
          else
            false
          end

        Snapshot.new(
          effective,
          cp,
          effective == :sp ? s.eff_prev_no_sp : effective,
          s.eff_prev,
          s.eff_prev_cp,
          in_pi_quote_window,
          effective == :ri ? s.ri_run + 1 : 0,
          in_nu_chain
        )
      end

      # ── Lookahead ─────────────────────────────────────────────────────────

      # The class at +index+, or nil past the end of the sequence.
      def class_at(pairs, index)
        entry = pairs[index]
        entry&.last
      end

      # LB15b holds when the final quote is last, or when what follows it
      # cannot itself open a line.
      def final_quote_closes?(pairs, index)
        nxt = class_at(pairs, index)
        return true if nxt.nil?

        QUOTE_CLOSERS.include?(nxt)
      end

      # The fourth LB28a sub-rule looks past any CM or ZWJ the cluster absorbs,
      # so the character it tests is the first significant one ahead.
      def next_significant_is_vf?(pairs, index)
        i = index
        while i < pairs.length
          cls = pairs[i].last
          return cls == :vf unless cm_zwj?(cls)

          i += 1
        end
        false
      end

      # ── The rule cascade ──────────────────────────────────────────────────

      # Whether a line break opportunity falls immediately before +pairs[index]+,
      # given the character before it and the context accumulated from
      # everything earlier.  +index+ is the position being decided, so
      # +index + 1+ supplies every lookahead the rules take.
      def breaks_before?(pairs, index, s)
        current = pairs[index]
        return true if current.nil? # LB3

        prev_cp, prev_class = pairs[index - 1]
        current_cp, current_class = current
        ahead = index + 1

        eff = effective_class(current_class, s.eff_prev)
        left = cm_zwj?(prev_class) ? s.eff_prev : prev_class

        # LB4
        return true if prev_class == :bk

        # LB5
        return false if prev_class == :cr && current_class == :lf
        return true if prev_class == :cr || prev_class == :lf ||
                       prev_class == :nl

        # LB6
        return false if MANDATORY.include?(current_class)

        # LB7
        return false if current_class == :sp || current_class == :zw

        # LB8
        return true if s.eff_prev_no_sp == :zw

        # LB8a
        return false if prev_class == :zwj

        # LB9
        if cm_zwj?(current_class) && !s.eff_prev.nil? &&
           !BLOCKS_ABSORB.include?(s.eff_prev)
          return false
        end

        # LB11
        return false if eff == :wj || left == :wj

        # LB12
        return false if left == :gl

        # LB12a
        if eff == :gl && !eff_in?(left, [:sp, :ba, :hy, :hh])
          return false
        end

        # LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS
        # that opens a number and follows a space, as in "equals .35".
        if prev_class == :sp && eff == :is && class_at(pairs, ahead) == :nu
          return true
        end

        # LB13
        return false if [:cl, :cp, :ex, :is, :sy].include?(eff)

        # LB14
        return false if s.eff_prev_no_sp == :op

        # LB15a
        return false if s.in_pi_quote_window

        # LB15b
        if pf_quote?(current_cp, eff) && final_quote_closes?(pairs, ahead)
          return false
        end

        # LB15d
        return false if eff == :is

        # LB16
        if eff == :ns && (s.eff_prev_no_sp == :cl || s.eff_prev_no_sp == :cp)
          return false
        end

        # LB17
        return false if eff == :b2 && s.eff_prev_no_sp == :b2

        # LB18
        return true if prev_class == :sp

        # LB19 and LB19a.  A quote neither breaks before nor after, except on
        # the OUTER side of an initial or final punctuation quote standing in
        # contiguous East Asian content — there the default break applies, so a
        # line may break at the quote boundary.  The inner side stays unbroken,
        # being the boundary inside the quote's own scope.
        if eff == :qu
          next_cp = pairs[ahead]&.first
          next_east_asian = !next_cp.nil? && east_asian_or_ambiguous?(next_cp)
          open_quote_in_east_asian =
            pi_quote?(current_cp, eff) && east_asian_or_ambiguous?(prev_cp) &&
            east_asian_or_ambiguous?(current_cp) && next_east_asian
          return false unless open_quote_in_east_asian
        end
        if left == :qu
          quote_cp = s.eff_prev_cp
          close_quote_in_east_asian =
            !quote_cp.nil? && pf_quote?(quote_cp, :qu) &&
            !s.eff_prev_prev_cp.nil? &&
            east_asian_or_ambiguous?(s.eff_prev_prev_cp) &&
            east_asian_or_ambiguous?(quote_cp) &&
            east_asian_or_ambiguous?(current_cp)
          return false unless close_quote_in_east_asian
        end

        # LB20
        return true if eff == :cb || left == :cb

        # LB20.1 and LB20a both require the hyphen's own left context to be
        # outside a word, the same start-of-segment set.
        hyphen_left_context_opens =
          s.eff_prev_prev.nil? ||
          HYPHEN_LEFT_OPENERS.include?(s.eff_prev_prev)

        # LB20.1, UCD 17.0: an explicit hyphen joins a following letter only
        # where its own left context is outside a word.  A mid-word HH falls
        # through to LB31.
        if left == :hh && (eff == :al || eff == :hl) &&
           hyphen_left_context_opens
          return false
        end

        # LB20a, with UCD 17.0's right side broadened to HL beside AL.
        if eff == :al || eff == :hl
          hyphen_carries_left =
            s.eff_prev == :hy || s.eff_prev == :hh ||
            s.eff_prev_cp == HYPHEN
          return false if hyphen_carries_left && hyphen_left_context_opens
        end

        # LB21
        return false if [:ba, :hy, :hh, :ns].include?(eff)
        return false if left == :bb

        # LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what
        # comes next unless that is itself HL.  A BA does not glue here.
        if s.eff_prev_prev == :hl && eff != :hl &&
           (s.eff_prev == :hy || s.eff_prev_cp == HYPHEN)
          return false
        end

        # LB21b
        return false if eff == :hl && left == :sy

        # LB22
        return false if eff == :in

        # LB23
        return false if eff == :nu && eff_in?(left, [:al, :hl])
        if (eff == :al || eff == :hl) && left == :nu
          return false
        end

        # LB23a
        if [:id, :eb, :em].include?(eff) && left == :pr
          return false
        end
        if eff == :po && eff_in?(left, [:id, :eb, :em])
          return false
        end

        # LB24
        if (eff == :al || eff == :hl) && eff_in?(left, [:pr, :po])
          return false
        end
        if (eff == :pr || eff == :po) && eff_in?(left, [:al, :hl])
          return false
        end

        # LB25, closing an open numeric chain with a CL or CP suffix and a
        # following PO or PR.
        if s.in_nu_chain && [:cl, :cp, :po, :pr].include?(eff)
          return false
        end

        # LB25, opening a chain
        if eff == :nu && eff_in?(left, [:pr, :po, :hy, :op, :is])
          return false
        end

        # LB25, chain body
        return false if eff == :nu && left == :nu

        # LB25, extending an open chain across a SY
        return false if eff == :nu && left == :sy && s.in_nu_chain

        # LB25, bracketed prefix: a PR joins an OP only when the OP itself opens
        # a number, and neither is East Asian Fullwidth, Wide or Halfwidth.
        if eff == :op && left == :pr && !east_asian_full_wide?(current_cp) &&
           !s.eff_prev_cp.nil? && !east_asian_full_wide?(s.eff_prev_cp) &&
           class_at(pairs, ahead) == :nu
          return false
        end

        # LB26
        if left == :jl && [:jl, :jv, :h2, :h3].include?(eff)
          return false
        end
        if eff_in?(left, [:jv, :h2]) && (eff == :jv || eff == :jt)
          return false
        end
        if eff_in?(left, [:jt, :h3]) && eff == :jt
          return false
        end

        # LB27
        if eff_in?(left, HANGUL) && (eff == :in || eff == :po)
          return false
        end
        if left == :pr && HANGUL.include?(eff)
          return false
        end

        # LB28
        if (eff == :al || eff == :hl) && eff_in?(left, [:al, :hl])
          return false
        end

        # LB28a, the aksara cluster rules.  U+25CC DOTTED CIRCLE carries class
        # AL and stands in for a cluster base throughout.
        left_is_aksara_base =
          eff_in?(left, [:ak, :as]) ||
          (s.eff_prev_cp == DOTTED_CIRCLE && s.eff_prev == :al)
        if left == :ap &&
           (eff == :ak || eff == :as || current_cp == DOTTED_CIRCLE)
          return false
        end
        if left_is_aksara_base && (eff == :vf || eff == :vi)
          return false
        end
        if s.eff_prev == :vi &&
           (s.eff_prev_prev == :ak || s.eff_prev_prev == :as ||
            s.eff_prev_prev_cp == DOTTED_CIRCLE) &&
           (eff == :ak || current_cp == DOTTED_CIRCLE)
          return false
        end
        if left_is_aksara_base &&
           (eff == :ak || eff == :as || current_cp == DOTTED_CIRCLE) &&
           next_significant_is_vf?(pairs, ahead)
          return false
        end

        # LB29
        if (eff == :al || eff == :hl) && left == :is
          return false
        end

        # LB30, where the bracket must not be East Asian Fullwidth, Wide or
        # Halfwidth.
        if eff == :op && eff_in?(left, [:al, :hl, :nu]) &&
           !east_asian_full_wide?(current_cp)
          return false
        end
        if [:al, :hl, :nu].include?(eff) && left == :cp &&
           !east_asian_full_wide?(prev_cp)
          return false
        end

        # LB30a
        return false if eff == :ri && (s.ri_run % 2) == 1

        # LB30b
        return false if eff == :em && left == :eb
        if eff == :em && !s.eff_prev_cp.nil? &&
           Grapheme.ext_pict?(s.eff_prev_cp) &&
           general_category(s.eff_prev_cp) == :cn
          return false
        end

        # LB31
        true
      end

      # ── Entry points ──────────────────────────────────────────────────────

      # One break-opportunity flag per boundary of the code point sequence, so a
      # sequence of n code points yields n + 1 flags — the shape the Lean
      # lineBreaks_length theorem fixes.
      #
      # Entry 0 is false — LB2 forbids a break at the start of text — and entry
      # n is true per LB3, which requires one at the end.
      def line_breaks(cps)
        pairs = cps.map { |cp| [cp, resolved_class(cp)] }
        out = []
        s = Snapshot.initial
        pairs.each_with_index do |(cp, cls), index|
          out << (index.zero? ? false : breaks_before?(pairs, index, s))
          s = advance(s, cp, cls)
        end
        out << true # LB3
        out
      end

      # The code point sequence split at every break opportunity — the runs a
      # renderer may place on separate lines.
      def line_runs(cps)
        breaks = line_breaks(cps)
        out = []
        current = []
        cps.each_with_index do |cp, index|
          current << cp
          if breaks[index + 1]
            out << current
            current = []
          end
        end
        out << current unless current.empty?
        out
      end
    end
  end
end
