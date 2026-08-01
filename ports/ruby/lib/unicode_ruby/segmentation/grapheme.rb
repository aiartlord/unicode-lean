# frozen_string_literal: true

require_relative "grapheme_tables"

module UnicodeRuby
  module Segmentation
    # UAX #29 default extended grapheme cluster segmentation.
    #
    # A byte-faithful transcription of the Rust reference
    # (`ports/rust/src/segmentation/grapheme.rs`), itself a transcription of the
    # Lean algorithm `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`.  The
    # active Lean tree proves `graphemeBreaks_eq_spec`, relating that algorithm
    # to the declarative UAX #29 GB1-GB999 specification.  The state fields, rule
    # order, and transitions below mirror that reference.
    #
    # Grapheme_Cluster_Break classes are Ruby symbols drawn from the fixed set
    # +:prepend :cr :lf :control :extend :regional_indicator :spacing_mark :l
    # :v :t :lv :lvt :zwj :other+.  Indic_Conjunct_Break classes are drawn from
    # +:linker :consonant :extend :none+.
    module Grapheme
      module_function

      # The property tables are grouped by property value (as in the UCD
      # source), not globally sorted by code point, so lookups scan linearly for
      # the covering range - mirroring the verified Lean +find?+.  Each class is
      # a partition, so at most one range covers a code point and the first match
      # is the only match.

      # Grapheme_Cluster_Break class of +cp+, +:other+ when uncovered.
      def lookup_gcb(cp)
        GraphemeTables::GCB_RANGES.each do |first, last, cls|
          return cls if first <= cp && cp <= last
        end
        :other
      end

      # Indic_Conjunct_Break class of +cp+, +:none+ when uncovered.
      def lookup_incb(cp)
        GraphemeTables::INCB_RANGES.each do |first, last, cls|
          return cls if first <= cp && cp <= last
        end
        :none
      end

      # Whether +cp+ has the Extended_Pictographic property.
      def ext_pict?(cp)
        GraphemeTables::EXTPICT_RANGES.each do |first, last|
          return true if first <= cp && cp <= last
        end
        false
      end

      # Running scan state, mirroring the Lean +State+.
      #
      # +prev_class+ is the Grapheme_Cluster_Break class of the previous code
      # point, or +nil+ at start-of-text.  +epic_state+ is the GB11 left-context
      # (+:none+, +:after_ep+, +:after_ep_zwj+, mirroring the Lean +EPicState+).
      # +incb_state+ is the GB9c left-context (+:none+, +:consonant+, +:linker+,
      # mirroring the Lean +InCBState+).  +ri_run+ is the length of the current
      # run of Regional_Indicator code points.
      State = Struct.new(:prev_class, :epic_state, :incb_state, :ri_run) do
        def self.initial
          new(nil, :none, :none, 0)
        end
      end

      # Whether a grapheme cluster break occurs immediately before +cp+ given the
      # running state +s+.  Implements UAX #29 GB1-GB999 in canonical order;
      # first match wins, the trailing GB999 breaks every otherwise-unmatched
      # pair.
      def should_break_before?(cp, s)
        bc = lookup_gcb(cp)
        incb = lookup_incb(cp)
        is_ep = ext_pict?(cp)
        pc = s.prev_class

        if pc.nil?
          true # GB1: sot ÷
        elsif pc == :cr && bc == :lf
          false # GB3: CR × LF
        elsif pc == :control || pc == :cr || pc == :lf
          true # GB4: (Control | CR | LF) ÷
        elsif bc == :control || bc == :cr || bc == :lf
          true # GB5: ÷ (Control | CR | LF)
        elsif pc == :l && (bc == :l || bc == :v || bc == :lv || bc == :lvt)
          false # GB6: L × (L | V | LV | LVT)
        elsif (pc == :lv || pc == :v) && (bc == :v || bc == :t)
          false # GB7: (LV | V) × (V | T)
        elsif (pc == :lvt || pc == :t) && bc == :t
          false # GB8: (LVT | T) × T
        elsif bc == :extend || bc == :zwj
          false # GB9: × (Extend | ZWJ)
        elsif bc == :spacing_mark
          false # GB9a: × SpacingMark
        elsif pc == :prepend
          false # GB9b: Prepend ×
        elsif s.incb_state == :linker && incb == :consonant
          false # GB9c: Consonant (Extend|Linker)* Linker (Extend|Linker)* × Consonant
        elsif s.epic_state == :after_ep_zwj && is_ep
          false # GB11: ExtPict Extend* ZWJ × ExtPict
        elsif bc == :regional_indicator && s.ri_run.odd?
          false # GB12/GB13: odd-parity RI run extends
        else
          true # GB999: Any ÷ Any
        end
      end

      # Update the running state after consuming +cp+.  Mirrors the Lean
      # +advance+.
      def advance(cp, s)
        bc = lookup_gcb(cp)
        incb = lookup_incb(cp)
        is_ep = ext_pict?(cp)

        epic_state =
          if is_ep
            :after_ep
          elsif s.epic_state == :after_ep && bc == :extend
            :after_ep
          elsif s.epic_state == :after_ep && bc == :zwj
            :after_ep_zwj
          else
            :none
          end

        incb_state =
          if incb == :consonant
            :consonant
          elsif s.incb_state == :consonant && incb == :linker
            :linker
          elsif s.incb_state == :consonant && incb == :extend
            :consonant
          elsif s.incb_state == :linker && incb == :linker
            :linker
          elsif s.incb_state == :linker && incb == :extend
            :linker
          else
            :none
          end

        ri_run = bc == :regional_indicator ? s.ri_run + 1 : 0

        State.new(bc, epic_state, incb_state, ri_run)
      end

      # Boundary mask of length +cps.length + 1+.  Entry +i+ is +true+ when a
      # grapheme cluster break occurs immediately before position +i+ - entry
      # +0+ is the GB1 start-of-text break, entry +cps.length+ the GB2
      # end-of-text break, both always +true+.  Mirrors the Lean
      # +graphemeBreaks+.  +cps+ is an Array of Integer code points.
      def grapheme_breaks(cps)
        bs = []
        s = State.initial
        cps.each do |cp|
          bs << should_break_before?(cp, s)
          s = advance(cp, s)
        end
        bs << true # GB2: eot ÷
        bs
      end

      # Split +cps+ into grapheme clusters (the code points between consecutive
      # boundaries).  +cps+ is an Array of Integer code points; the result is an
      # Array of Arrays of Integer code points.
      def grapheme_clusters(cps)
        breaks = grapheme_breaks(cps)
        out = []
        cur = []
        cps.each_with_index do |cp, i|
          if breaks[i] && !cur.empty?
            out << cur
            cur = []
          end
          cur << cp
        end
        out << cur unless cur.empty?
        out
      end
    end
  end
end
