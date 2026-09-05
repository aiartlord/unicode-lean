# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Display
      # Which bidi format controls serve a purpose, and which do not.
      #
      # Direct port of `Unicode/Security/Display/BidiControlPurpose.lean`. The
      # nine UAX #9 format controls exist to manage right-to-left text: a span is
      # doing that job when the text it encloses is right-to-left, or when it
      # forces left-to-right text inside a right-to-left context. A span
      # enclosing no strong right-to-left character in a left-to-right context
      # manages nothing (`LRI user PDI` around Latin text, `LRO return PDF`
      # around a keyword), and an unbalanced control never manages anything.
      # Every Trojan Source payload is a control of that kind; a balanced
      # embedding around an Arabic string literal is the opposite case and
      # renders the literal as written.
      #
      # This is not source-region filtering: the question is asked of every
      # control wherever it sits, and it is decided from the codepoints the span
      # encloses, never from where a tokenizer would place it.
      #
      # Rule, as the Lean `walk` states it:
      #
      # - An opener pushes a span: its position, whether it is an isolate
      #   (closed by PDI) or an embedding/override (closed by PDF), and whether
      #   it is right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right
      #   (LRE, LRO, LRI).
      # - Every other codepoint is recorded against the innermost open span
      #   only: strong right-to-left (R or AL), strong left-to-right (L), or
      #   ASCII code syntax. A nested span manages its own content.
      # - PDF closes the top span when it is an embedding; against an isolate on
      #   top, or an empty stack, it is an orphan. PDI closes down to the
      #   innermost isolate, implicitly terminating the embeddings above it,
      #   which are thereby unbalanced; with no isolate open it is an orphan.
      # - A closed span is purposeful iff its direct content is exactly its own
      #   direction and carries no code syntax; a left-to-right span
      #   additionally needs right-to-left context (an enclosing right-to-left
      #   span, or a paragraph whose first strong character is right-to-left).
      # - Reported: every orphan, every opener still open at the end, every
      #   embedding a PDI terminated implicitly, and both ends of every closed
      #   span that was not purposeful.
      #
      # The strong-direction predicates are the port's own
      # `Ucd.strong_rtl?` / `strong_ltr?` over the pinned bidi table.
      module BidiControlPurpose
        # The ASCII codepoints a Trojan Source payload moves: quotes, brackets,
        # comment markers, statement separators, operators. Prose punctuation,
        # space and digits are not in the set.
        CODE_SYNTAX = [
          0x22, 0x27, 0x60, 0x28, 0x29, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x5C, 0x2A,
          0x23, 0x3B, 0x3C, 0x3E, 0x3D, 0x2B, 0x7C, 0x26, 0x25, 0x24, 0x40, 0x5E,
          0x7E
        ].freeze

        # One open span: where it opened, how it closes, its direction in
        # effect, and what has appeared directly inside it.
        OpenSpan = Struct.new(:pos, :isolate, :rtl_kind, :saw_rtl, :saw_ltr, :saw_syntax)

        module_function

        # RLE, RLO, RLI, or FSI (whose direction resolves from its content).
        def opens_rtl_kind?(cp)
          cp == 0x202B || cp == 0x202E || cp == 0x2067 || cp == 0x2068
        end

        # LRE, LRO, LRI.
        def opens_ltr_kind?(cp)
          cp == 0x202A || cp == 0x202D || cp == 0x2066
        end

        # LRI, RLI, FSI.
        def opens_isolate_kind?(cp)
          cp == 0x2066 || cp == 0x2067 || cp == 0x2068
        end

        def code_syntax?(cp)
          CODE_SYNTAX.include?(cp)
        end

        # UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
        # character is right-to-left.
        def paragraph_rtl?(input)
          input.each do |cp|
            return true if Ucd.strong_rtl?(cp)
            return false if Ucd.strong_ltr?(cp)
          end
          false
        end

        # A closed span is purposeful iff its direct content is exactly its own
        # direction and carries no code syntax; a left-to-right span
        # additionally needs right-to-left context.
        def span_purposeful?(span, enclosing, paragraph_rtl)
          if span.rtl_kind
            span.saw_rtl && !span.saw_ltr && !span.saw_syntax
          else
            in_rtl_context = paragraph_rtl || enclosing.any?(&:rtl_kind)
            in_rtl_context && span.saw_ltr && !span.saw_rtl && !span.saw_syntax
          end
        end

        # Positions of the purposeless bidi format controls in the input, in
        # input order. Empty iff every control is balanced and manages
        # right-to-left text.
        def purposeless_control_positions(input)
          paragraph_rtl = paragraph_rtl?(input)
          # The stack's last element is the innermost open span.
          stack = []
          reported = []

          input.each_with_index do |cp, idx|
            if opens_rtl_kind?(cp) || opens_ltr_kind?(cp)
              stack << OpenSpan.new(idx, opens_isolate_kind?(cp), opens_rtl_kind?(cp), false, false, false)
            elsif cp == 0x202C
              # PDF closes the top embedding; an isolate on top or an empty
              # stack makes it an orphan.
              if stack.empty? || stack.last.isolate
                reported << idx
              else
                top = stack.pop
                unless span_purposeful?(top, stack, paragraph_rtl)
                  reported << top.pos
                  reported << idx
                end
              end
            elsif cp == 0x2069
              # PDI closes down to the innermost isolate; the embeddings above
              # it are terminated implicitly and so unbalanced. No isolate
              # open: orphan.
              iso_index = stack.rindex(&:isolate)
              if iso_index.nil?
                reported << idx
              else
                stack[(iso_index + 1)..].each { |dropped| reported << dropped.pos }
                closed = stack[iso_index]
                stack.slice!(iso_index..)
                unless span_purposeful?(closed, stack, paragraph_rtl)
                  reported << closed.pos
                  reported << idx
                end
              end
            elsif !stack.empty?
              top = stack.last
              top.saw_rtl ||= Ucd.strong_rtl?(cp)
              top.saw_ltr ||= Ucd.strong_ltr?(cp)
              top.saw_syntax ||= code_syntax?(cp)
            end
          end

          # Every opener still open at the end is unbalanced.
          stack.each { |open| reported << open.pos }

          reported.uniq.sort
        end

        # True iff the input carries at least one purposeless bidi format
        # control.
        def purposeless_control?(input)
          !purposeless_control_positions(input).empty?
        end

        # Position and codepoint of the first purposeless control as
        # `[pos, cp]`, or nil when every control is purposeful.
        def first_purposeless_control(input)
          positions = purposeless_control_positions(input)
          return nil if positions.empty?

          [positions[0], input[positions[0]]]
        end
      end
    end
  end
end
