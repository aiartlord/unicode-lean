# frozen_string_literal: true

module UnicodeRuby
  module Security
    module Covert
      # Detection of Trojan-Source-class bidi-control balance hazards
      # (CVE-2021-42574 / CVE-2021-42694).  Walks the input with per-type
      # stacks and produces four independent sub-threats.
      module BidiControlBalance
        Verdict = Struct.new(
          :kind, :sub, :bidi_positions,
          :emb_open_count, :emb_pop_count, :iso_open_count, :iso_pop_count,
          :max_depth
        )

        # UAX #9 §3.3.2 cap on the stack-of-stacks depth.
        UAX_DEPTH_LIMIT = 125

        module_function

        # LRE (202A), RLE (202B), LRO (202D), RLO (202E).
        def opens_embedding?(cp)
          cp == 0x202A || cp == 0x202B || cp == 0x202D || cp == 0x202E
        end

        def pdf?(cp)
          cp == 0x202C
        end

        # LRI (2066), RLI (2067), FSI (2068).
        def opens_isolate?(cp)
          cp == 0x2066 || cp == 0x2067 || cp == 0x2068
        end

        def pdi?(cp)
          cp == 0x2069
        end

        def bidi_format_control?(cp)
          opens_embedding?(cp) || pdf?(cp) || opens_isolate?(cp) || pdi?(cp)
        end

        def detect(input)
          v = Verdict.new(Calculus::ClassificationKind::CLEAR, nil, [], 0, 0, 0, 0, 0)
          emb_stack = 0
          iso_stack = 0
          orphans = []

          input.each_with_index do |cp, i|
            next unless bidi_format_control?(cp)

            v.bidi_positions << i
            if opens_embedding?(cp)
              emb_stack += 1
              v.emb_open_count += 1
              depth = emb_stack + iso_stack
              v.max_depth = depth if depth > v.max_depth
            elsif pdf?(cp)
              v.emb_pop_count += 1
              if emb_stack > 0
                emb_stack -= 1
              else
                orphans << i
              end
            elsif opens_isolate?(cp)
              iso_stack += 1
              v.iso_open_count += 1
              depth = emb_stack + iso_stack
              v.max_depth = depth if depth > v.max_depth
            elsif pdi?(cp)
              v.iso_pop_count += 1
              if iso_stack > 0
                iso_stack -= 1
              else
                orphans << i
              end
            end
          end

          return v if v.bidi_positions.empty?

          if v.max_depth > UAX_DEPTH_LIMIT
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "DepthExceeded"
            return v
          end
          unless orphans.empty?
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "OrphanPop"
            return v
          end
          if emb_stack > 0
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "UnbalancedEmbedding"
            return v
          end
          if iso_stack > 0
            v.kind = Calculus::ClassificationKind::HAZARD
            v.sub = "UnbalancedIsolate"
            return v
          end
          v
        end
      end
    end
  end
end
