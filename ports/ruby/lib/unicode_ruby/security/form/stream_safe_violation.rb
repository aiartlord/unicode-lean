# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Form
      # Stream-Safe-Text-Format-violation detection — inputs whose consecutive
      # non-starter run exceeds the UAX #15 §13 stream-safe limit of 30.  Such
      # an input (the canonical "Zalgo" shape, a single base codepoint followed
      # by a long combining-mark run) forces unbounded combining-mark buffers in
      # receiver-side streaming normalization (toNFC / toNFD / toNFKC / toNFKD)
      # and is a known DoS vector.
      #
      # Byte-faithful port of the Rust reference
      # (`ports/rust/src/security/form/stream_safe_violation.rs`), itself a port
      # of `Unicode/Security/Form/StreamSafeViolation.lean`.  UAX #15 §13 defines
      # Stream-Safe Text Format as the remediation: insert U+034F COMBINING
      # GRAPHEME JOINER (a starter) after every 30 consecutive non-starters,
      # which bounds the normalization buffer.
      #
      # A codepoint is a non-starter iff its Canonical_Combining_Class is
      # non-zero (UAX #15 D49).  Combining class is read from the port's own
      # bundled UCD table via `Ucd.ccc`, never a host normalizer.
      #
      # Sub-threat: StreamSafeOverrun(base_pos, run_len) — the first non-starter
      # run whose length exceeds the stream-safe limit.  base_pos is the index
      # of that run's first non-starter codepoint.
      module StreamSafeViolation
        # UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
        # non-starters permitted before a COMBINING GRAPHEME JOINER must be
        # inserted.
        STREAM_SAFE_LIMIT = 30

        # A sub-threat this detector can fire.  `kind` is the discriminant;
        # `base_pos` is the index of the overrunning run's first non-starter
        # codepoint and `run_len` is that run's length.
        SubThreat = Struct.new(:kind, :base_pos, :run_len) do
          # Human-facing classification tag for this sub-threat.
          def tag
            case kind
            when :stream_safe_overrun then "StreamSafeOverrun"
            else
              raise "StreamSafeViolation::SubThreat#tag: unknown kind #{kind.inspect}"
            end
          end
        end

        # Top-level classification.  `kind` is :clear or :hazard; on a hazard,
        # `sub` is the SubThreat, `positions` the implicated indices, and
        # `decoded` the decoded byte context (always empty for this detector,
        # mirroring the spec's Classification.hazard shape).
        Classification = Struct.new(:kind, :sub, :positions, :decoded) do
          # True iff the input is clear.
          def clear?
            case kind
            when :clear then true
            when :hazard then false
            else
              raise "StreamSafeViolation::Classification#clear?: unknown kind #{kind.inspect}"
            end
          end

          # Human-facing tag for a hazard, or nil when clear.
          def tag
            case kind
            when :clear then nil
            when :hazard then sub.tag
            else
              raise "StreamSafeViolation::Classification#tag: unknown kind #{kind.inspect}"
            end
          end

          # Implicated positions (empty when clear).
          def implicated_positions
            case kind
            when :clear then []
            when :hazard then positions
            else
              raise "StreamSafeViolation::Classification#implicated_positions: unknown kind #{kind.inspect}"
            end
          end
        end

        # Verdict — the structured output of `detect`.  The run-inventory
        # summaries (max_run_len, overrun_count, total_non_starters) are exposed
        # so downstream callers can size the buffer pressure a streaming
        # normalizer would see.
        Verdict = Struct.new(:input, :classify, :max_run_len, :overrun_count, :total_non_starters)

        module_function

        # True iff `cp` is a non-starter — a codepoint with non-zero
        # Canonical_Combining_Class (UAX #15 D49).  Starters have CCC = 0.
        def non_starter?(cp)
          Ucd.ccc(cp) != 0
        end

        # Inventory of [start_index, length] for every maximal non-starter run
        # in `input`.  A run opens on the first non-starter, its start index is
        # fixed to that codepoint's absolute index, and it closes (emitting its
        # [start, length] pair) on the next starter or at end of input.
        def non_starter_runs(input)
          runs = []
          cur_start = nil
          cur_len = 0
          input.each_index do |i|
            if non_starter?(input[i])
              cur_start = i if cur_start.nil?
              cur_len += 1
            else
              runs << [cur_start, cur_len] unless cur_start.nil?
              cur_start = nil
              cur_len = 0
            end
          end
          runs << [cur_start, cur_len] unless cur_start.nil?
          runs
        end

        # First non-starter run whose length exceeds STREAM_SAFE_LIMIT, as
        # [start_index, length], or nil when none does.
        def first_overrun(input)
          non_starter_runs(input).find { |_start, len| len > STREAM_SAFE_LIMIT }
        end

        # Longest non-starter run length in `input`.
        def max_run_len(input)
          non_starter_runs(input).reduce(0) { |acc, (_start, len)| len > acc ? len : acc }
        end

        # Number of distinct non-starter runs that exceed STREAM_SAFE_LIMIT.
        def overrun_count(input)
          non_starter_runs(input).reduce(0) do |acc, (_start, len)|
            len > STREAM_SAFE_LIMIT ? acc + 1 : acc
          end
        end

        # Total non-starter codepoints in `input` (sum of all run lengths).
        def total_non_starters(input)
          non_starter_runs(input).reduce(0) { |acc, (_start, len)| acc + len }
        end

        # The detection function.  Fires StreamSafeOverrun on the first
        # non-starter run whose length exceeds STREAM_SAFE_LIMIT.
        def detect(input)
          overrun = first_overrun(input)
          classification =
            if overrun.nil?
              Classification.new(:clear, nil, [], [])
            else
              base_pos, run_len = overrun
              Classification.new(
                :hazard,
                SubThreat.new(:stream_safe_overrun, base_pos, run_len),
                [base_pos],
                []
              )
            end
          Verdict.new(
            input.dup,
            classification,
            max_run_len(input),
            overrun_count(input),
            total_non_starters(input)
          )
        end
      end
    end
  end
end
