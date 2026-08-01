defmodule UnicodeSecurity.Covert.BidiControlBalance do
  defstruct kind: :clear,
            sub: nil,
            bidi_positions: [],
            emb_open_count: 0,
            emb_pop_count: 0,
            iso_open_count: 0,
            iso_pop_count: 0,
            max_depth: 0

  @uax_depth_limit 125

  def opens_embedding?(cp), do: cp in [0x202A, 0x202B, 0x202D, 0x202E]
  def pdf?(cp), do: cp == 0x202C
  def opens_isolate?(cp), do: cp in [0x2066, 0x2067, 0x2068]
  def pdi?(cp), do: cp == 0x2069

  def bidi_format_control?(cp),
    do: opens_embedding?(cp) or pdf?(cp) or opens_isolate?(cp) or pdi?(cp)

  def detect(input) do
    init = {%__MODULE__{}, 0, 0, []}

    {v, emb_stack, iso_stack, orphans} =
      input
      |> Enum.with_index()
      |> Enum.reduce(init, fn {cp, i}, {v, emb, iso, orphans} ->
        if bidi_format_control?(cp) do
          v = %{v | bidi_positions: v.bidi_positions ++ [i]}

          cond do
            opens_embedding?(cp) ->
              emb = emb + 1

              {%{
                 v
                 | emb_open_count: v.emb_open_count + 1,
                   max_depth: max(v.max_depth, emb + iso)
               }, emb, iso, orphans}

            pdf?(cp) ->
              if emb > 0 do
                {%{v | emb_pop_count: v.emb_pop_count + 1}, emb - 1, iso, orphans}
              else
                {%{v | emb_pop_count: v.emb_pop_count + 1}, emb, iso, orphans ++ [i]}
              end

            opens_isolate?(cp) ->
              iso = iso + 1

              {%{
                 v
                 | iso_open_count: v.iso_open_count + 1,
                   max_depth: max(v.max_depth, emb + iso)
               }, emb, iso, orphans}

            pdi?(cp) ->
              if iso > 0 do
                {%{v | iso_pop_count: v.iso_pop_count + 1}, emb, iso - 1, orphans}
              else
                {%{v | iso_pop_count: v.iso_pop_count + 1}, emb, iso, orphans ++ [i]}
              end
          end
        else
          {v, emb, iso, orphans}
        end
      end)

    cond do
      v.bidi_positions == [] ->
        v

      v.max_depth > @uax_depth_limit ->
        %{v | kind: :hazard, sub: %{tag: "DepthExceeded", max_depth: v.max_depth}}

      orphans != [] ->
        %{v | kind: :hazard, sub: %{tag: "OrphanPop", positions: orphans}}

      emb_stack > 0 ->
        %{
          v
          | kind: :hazard,
            sub: %{
              tag: "UnbalancedEmbedding",
              open_count: v.emb_open_count,
              pop_count: v.emb_pop_count
            }
        }

      iso_stack > 0 ->
        %{
          v
          | kind: :hazard,
            sub: %{
              tag: "UnbalancedIsolate",
              open_count: v.iso_open_count,
              pop_count: v.iso_pop_count
            }
        }

      true ->
        v
    end
  end
end
