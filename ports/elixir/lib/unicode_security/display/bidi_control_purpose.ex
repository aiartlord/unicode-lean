defmodule UnicodeSecurity.Display.BidiControlPurpose do
  @moduledoc """
  Which bidi format controls serve a purpose, and which do not.

  Direct port of `Unicode/Security/Display/BidiControlPurpose.lean`. The nine
  UAX #9 format controls exist to manage right-to-left text: a span is doing
  that job when the text it encloses is right-to-left, or when it forces
  left-to-right text inside a right-to-left context. A span enclosing no strong
  right-to-left character in a left-to-right context manages nothing (`LRI user
  PDI` around Latin text, `LRO return PDF` around a keyword), and an unbalanced
  control never manages anything. Every Trojan Source payload is a control of
  that kind; a balanced embedding around an Arabic string literal is the
  opposite case and renders the literal as written.

  This is not source-region filtering: the question is asked of every control
  wherever it sits, and it is decided from the codepoints the span encloses,
  never from where a tokenizer would place it.

  Rule, as the Lean `walk` states it:

    * An opener pushes a span: its position, whether it is an isolate (closed
      by PDI) or an embedding/override (closed by PDF), and whether it is
      right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
      LRI).
    * Every other codepoint is recorded against the innermost open span only:
      strong right-to-left (R or AL), strong left-to-right (L), or ASCII code
      syntax. A nested span manages its own content.
    * PDF closes the top span when it is an embedding; against an isolate on
      top, or an empty stack, it is an orphan. PDI closes down to the innermost
      isolate, implicitly terminating the embeddings above it, which are
      thereby unbalanced; with no isolate open it is an orphan.
    * A closed span is purposeful iff its direct content is exactly its own
      direction and carries no code syntax; a left-to-right span additionally
      needs right-to-left context (an enclosing right-to-left span, or a
      paragraph whose first strong character is right-to-left).
    * Reported: every orphan, every opener still open at the end, every
      embedding a PDI terminated implicitly, and both ends of every closed span
      that was not purposeful.

  The strong-direction predicates are the port's own `Ucd.strong_rtl?` /
  `Ucd.strong_ltr?` over the pinned bidi table. Positions are 0-based.
  """

  alias UnicodeSecurity.Ucd

  # The ASCII codepoints a Trojan Source payload moves: quotes, brackets,
  # comment markers, statement separators, operators. Prose punctuation, space
  # and digits are not in the set.
  @code_syntax [
    0x22, 0x27, 0x60, 0x28, 0x29, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x5C, 0x2A,
    0x23, 0x3B, 0x3C, 0x3E, 0x3D, 0x2B, 0x7C, 0x26, 0x25, 0x24, 0x40, 0x5E,
    0x7E
  ]

  @doc "RLE, RLO, RLI, or FSI (whose direction resolves from its content)."
  def opens_rtl_kind?(cp), do: cp in [0x202B, 0x202E, 0x2067, 0x2068]

  @doc "LRE, LRO, LRI."
  def opens_ltr_kind?(cp), do: cp in [0x202A, 0x202D, 0x2066]

  @doc "LRI, RLI, FSI."
  def opens_isolate_kind?(cp), do: cp in [0x2066, 0x2067, 0x2068]

  def code_syntax?(cp), do: cp in @code_syntax

  @doc """
  UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
  character is right-to-left.
  """
  def paragraph_rtl?(input) do
    Enum.find_value(input, false, fn cp ->
      cond do
        Ucd.strong_rtl?(cp) -> true
        Ucd.strong_ltr?(cp) -> false
        true -> nil
      end
    end)
  end

  # A closed span is purposeful iff its direct content is exactly its own
  # direction and carries no code syntax; a left-to-right span additionally
  # needs right-to-left context.
  defp span_purposeful?(span, enclosing, paragraph_rtl) do
    if span.rtl_kind do
      span.saw_rtl and not span.saw_ltr and not span.saw_syntax
    else
      in_rtl_context = paragraph_rtl or Enum.any?(enclosing, & &1.rtl_kind)
      in_rtl_context and span.saw_ltr and not span.saw_rtl and not span.saw_syntax
    end
  end

  @doc """
  0-based positions of the purposeless bidi format controls in the input, in
  input order. Empty iff every control is balanced and manages right-to-left
  text.
  """
  def purposeless_control_positions(input) do
    paragraph_rtl = paragraph_rtl?(input)

    # The stack's head is the innermost open span, as in the Lean list.
    {stack, reported} =
      input
      |> Enum.with_index()
      |> Enum.reduce({[], []}, fn {cp, idx}, {stack, reported} ->
        step(cp, idx, stack, reported, paragraph_rtl)
      end)

    # Every opener still open at the end is unbalanced.
    (reported ++ Enum.map(stack, & &1.pos))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp step(cp, idx, stack, reported, paragraph_rtl) do
    cond do
      opens_rtl_kind?(cp) or opens_ltr_kind?(cp) ->
        span = %{
          pos: idx,
          isolate: opens_isolate_kind?(cp),
          rtl_kind: opens_rtl_kind?(cp),
          saw_rtl: false,
          saw_ltr: false,
          saw_syntax: false
        }

        {[span | stack], reported}

      # PDF closes the top embedding; an isolate on top or an empty stack makes
      # it an orphan.
      cp == 0x202C ->
        case stack do
          [%{isolate: false} = top | below] ->
            if span_purposeful?(top, below, paragraph_rtl),
              do: {below, reported},
              else: {below, reported ++ [top.pos, idx]}

          other ->
            {other, reported ++ [idx]}
        end

      # PDI closes down to the innermost isolate; the embeddings above it are
      # terminated implicitly and so unbalanced. No isolate open: orphan.
      cp == 0x2069 ->
        case Enum.split_while(stack, fn span -> not span.isolate end) do
          {dropped, [iso | below]} ->
            reported = reported ++ Enum.map(dropped, & &1.pos)

            if span_purposeful?(iso, below, paragraph_rtl),
              do: {below, reported},
              else: {below, reported ++ [iso.pos, idx]}

          {_no_isolate, []} ->
            {stack, reported ++ [idx]}
        end

      true ->
        case stack do
          [top | below] ->
            top = %{
              top
              | saw_rtl: top.saw_rtl or Ucd.strong_rtl?(cp),
                saw_ltr: top.saw_ltr or Ucd.strong_ltr?(cp),
                saw_syntax: top.saw_syntax or code_syntax?(cp)
            }

            {[top | below], reported}

          [] ->
            {[], reported}
        end
    end
  end

  @doc "True iff the input carries at least one purposeless bidi format control."
  def purposeless_control?(input), do: purposeless_control_positions(input) != []

  @doc """
  0-based position and codepoint of the first purposeless control as
  `{pos, cp}`, or `nil` when every control is purposeful.
  """
  def first_purposeless_control(input) do
    case purposeless_control_positions(input) do
      [] -> nil
      [pos | _rest] -> {pos, Enum.at(input, pos)}
    end
  end
end
