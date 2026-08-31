# frozen_string_literal: true

module UnicodeRuby
  module Security
    # UCD-table-backed support module for the identity-spoofing detector
    # family — NFC/NFD/NFKC/NFKD normalization, script lookup, UTS #39
    # identifier-status / restriction-level classification, and UAX #21 case
    # mapping.  All data is loaded lazily from the bundled UCD files in the
    # port's `data/` directory; normalization and casing are computed from the
    # pinned tables, never from the Ruby interpreter's built-in Unicode.
    module Ucd
      module RestrictionLevel
        ASCII_ONLY = :ascii_only
        SINGLE_SCRIPT = :single_script
        HIGHLY_RESTRICTIVE = :highly_restrictive
        MODERATELY_RESTRICTIVE = :moderately_restrictive
        MINIMALLY_RESTRICTIVE = :minimally_restrictive
        UNRESTRICTED = :unrestricted
      end

      # The locales SpecialCasing.txt distinguishes.  DEFAULT covers everything
      # not tagged Turkish / Azeri / Lithuanian.
      module Locale
        DEFAULT = :default
        TURKISH = :turkish
        AZERI = :azeri
        LITHUANIAN = :lithuanian
      end

      # The strong Bidi_Class distinction the display layer needs.
      module BidiStrong
        R = :r
        AL = :al
        L = :l
        OTHER = :other
      end

      # UAX #11 East_Asian_Width class.
      module EastAsianWidth
        A = :a
        F = :f
        H = :h
        N = :n
        NA = :na
        W = :w
      end

      # Joining_Type, the cursive-joining behaviour a character has in scripts
      # like Arabic. RFC 5892 Appendix A.1 uses it to decide whether a ZERO
      # WIDTH NON-JOINER sits in a position its script actually requires.
      module JoiningType
        JOIN_CAUSING = :c
        DUAL_JOINING = :d
        LEFT_JOINING = :l
        RIGHT_JOINING = :r
        TRANSPARENT = :t
        NON_JOINING = :u
      end

      module_function

      # ── Parsing helpers ───────────────────────────────────────────────────

      def parse_hex(str)
        token = str.strip
        return nil if token.empty?
        return nil unless token.match?(/\A[0-9A-Fa-f]+\z/)

        token.to_i(16)
      end

      def strip_comment_and_trim(line)
        idx = line.index("#")
        body = idx.nil? ? line : line[0...idx]
        body.strip
      end

      def parse_range_field(str)
        s = str.strip
        idx = s.index("..")
        if idx
          a = parse_hex(s[0...idx])
          b = parse_hex(s[(idx + 2)..])
          return nil if a.nil? || b.nil?

          [a, b]
        else
          a = parse_hex(s)
          return nil if a.nil?

          [a, a]
        end
      end

      # Index of the count of leading array elements for which the block is
      # true (the array is sorted so the predicate is monotone).
      def partition_point(arr)
        lo = 0
        hi = arr.length
        while lo < hi
          mid = lo + ((hi - lo) / 2)
          if yield(arr[mid])
            lo = mid + 1
          else
            hi = mid
          end
        end
        lo
      end

      # ── UnicodeData.txt — CCC + canonical / compatibility decomposition ────

      # Each entry: { ccc: Integer, canonical: Array|nil, compat: Array|nil }.
      def ucd_table
        @ucd_table ||= parse_unicode_data
      end

      def parse_unicode_data
        out = {}
        UnicodeRuby.read_data("UnicodeData.txt").each_line do |raw|
          line = raw.chomp
          next if line.empty? || line.start_with?("#")

          fields = line.split(";", -1)
          next if fields.length < 6

          cp = parse_hex(fields[0])
          next if cp.nil?

          ccc_field = fields[3].strip
          unless ccc_field.match?(/\A[0-9]+\z/)
            raise "UnicodeData.txt: CCC field for U+#{format('%04X', cp)} is not an integer (#{fields[3].inspect})"
          end
          ccc_val = ccc_field.to_i

          decomp_field = fields[5].strip
          canonical = nil
          compat = nil
          unless decomp_field.empty?
            if decomp_field.start_with?("<")
              close = decomp_field.index(">")
              after_tag = close ? decomp_field[(close + 1)..] : decomp_field
              parts = after_tag.split(/\s+/).map { |t| parse_hex(t) }.compact
              compat = parts unless parts.empty?
            else
              parts = decomp_field.split(/\s+/).map { |t| parse_hex(t) }.compact
              canonical = parts unless parts.empty?
            end
          end

          out[cp] = { ccc: ccc_val, canonical: canonical, compat: compat }
        end
        out
      end

      # UAX #44 §5.7.4: codepoints absent from the table have CCC = 0.
      def ccc(cp)
        entry = ucd_table[cp]
        entry.nil? ? 0 : entry[:ccc]
      end

      # ── DerivedJoiningType.txt — RFC 5892 Appendix A.1 support ────────────

      def joining_type_of_token(token)
        case token
        when "C" then JoiningType::JOIN_CAUSING
        when "D" then JoiningType::DUAL_JOINING
        when "L" then JoiningType::LEFT_JOINING
        when "R" then JoiningType::RIGHT_JOINING
        when "T" then JoiningType::TRANSPARENT
        else JoiningType::NON_JOINING
        end
      end

      def parse_joining_types
        rows = []
        UnicodeRuby.read_data("DerivedJoiningType.txt").each_line do |raw|
          line = raw.chomp
          hash = line.index("#")
          line = line[0...hash] if hash
          body = line.strip
          next if body.empty?

          semi = body.index(";")
          next if semi.nil?

          range = parse_range_field(body[0...semi])
          next if range.nil?

          rows << [range[0], range[1], joining_type_of_token(body[(semi + 1)..].strip)]
        end
        rows.sort_by! { |row| row[0] }
        rows
      end

      def joining_type_table
        @joining_type_table ||= parse_joining_types
      end

      # Joining_Type for one codepoint. The file's @missing line declares
      # Non_Joining over the whole space, so an unlisted codepoint is
      # Non_Joining.
      def joining_type(cp)
        table = joining_type_table
        lo = 0
        hi = table.length
        while lo < hi
          mid = lo + ((hi - lo) / 2)
          rlo, rhi, cls = table[mid]
          if cp < rlo
            hi = mid
          elsif cp > rhi
            lo = mid + 1
          else
            return cls
          end
        end
        JoiningType::NON_JOINING
      end

      # True iff cp has Canonical_Combining_Class 9, the Virama used to request
      # an explicit conjunct in scripts like Devanagari.
      def virama?(cp)
        ccc(cp) == 9
      end

      # ── EastAsianWidth.txt — UAX #11 East_Asian_Width lookup ──────────────

      def east_asian_width_of_token(token)
        case token
        when "A" then EastAsianWidth::A
        when "F" then EastAsianWidth::F
        when "H" then EastAsianWidth::H
        when "Na" then EastAsianWidth::NA
        when "W" then EastAsianWidth::W
        else EastAsianWidth::N
        end
      end

      def parse_east_asian_width
        rows = []
        UnicodeRuby.read_data("EastAsianWidth.txt").each_line do |raw|
          line = raw.chomp
          hash = line.index("#")
          line = line[0...hash] if hash
          body = line.strip
          next if body.empty?

          semi = body.index(";")
          next if semi.nil?

          range = parse_range_field(body[0...semi])
          next if range.nil?

          rows << [range[0], range[1], east_asian_width_of_token(body[(semi + 1)..].strip)]
        end
        rows.sort_by! { |row| row[0] }
        rows
      end

      def east_asian_width_table
        @east_asian_width_table ||= parse_east_asian_width
      end

      # East_Asian_Width for one codepoint. The file's @missing line declares N
      # over the whole space, so an unlisted codepoint is Neutral.
      def east_asian_width(cp)
        table = east_asian_width_table
        lo = 0
        hi = table.length
        while lo < hi
          mid = lo + ((hi - lo) / 2)
          rlo, rhi, cls = table[mid]
          if cp < rlo
            hi = mid
          elsif cp > rhi
            lo = mid + 1
          else
            return cls
          end
        end
        EastAsianWidth::N
      end

      # ── DerivedBidiClass.txt — strong Bidi_Class lookup ────────────────────

      def bidi_table
        @bidi_table ||= parse_derived_bidi
      end

      def strong_of_short(token)
        case token
        when "R" then BidiStrong::R
        when "AL" then BidiStrong::AL
        when "L" then BidiStrong::L
        else BidiStrong::OTHER
        end
      end

      def strong_of_long(token)
        case token
        when "Right_To_Left" then BidiStrong::R
        when "Arabic_Letter" then BidiStrong::AL
        when "Left_To_Right" then BidiStrong::L
        else BidiStrong::OTHER
        end
      end

      def parse_derived_bidi
        explicit = []
        defaults = []
        UnicodeRuby.read_data("DerivedBidiClass.txt").each_line do |raw|
          line = raw.chomp
          if line.start_with?("# @missing:")
            rest = line["# @missing:".length..]
            semi = rest.index(";")
            if semi
              range = rest[0...semi]
              cls = rest[(semi + 1)..].strip
              lohi = parse_range_field(range)
              defaults << [lohi[0], lohi[1], strong_of_long(cls)] if lohi
            end
            next
          end
          hash = line.index("#")
          body = (hash ? line[0...hash] : line).strip
          next if body.empty?

          semi = body.index(";")
          next if semi.nil?

          range = body[0...semi]
          cls = body[(semi + 1)..].strip
          lohi = parse_range_field(range)
          explicit << [lohi[0], lohi[1], strong_of_short(cls)] if lohi
        end
        explicit.sort_by! { |entry| entry[0] }
        { explicit: explicit, defaults: defaults }
      end

      # Full Bidi_Class lookup (strong distinction only): explicit range first,
      # then the last matching @missing default, then L.
      def bidi_strong(cp)
        table = bidi_table
        explicit = table[:explicit]
        lo = 0
        hi = explicit.length
        while lo < hi
          mid = lo + ((hi - lo) / 2)
          rlo, rhi, cls = explicit[mid]
          if cp < rlo
            hi = mid
          elsif cp > rhi
            lo = mid + 1
          else
            return cls
          end
        end
        result = BidiStrong::L
        table[:defaults].each do |rlo, rhi, cls|
          result = cls if rlo <= cp && cp <= rhi
        end
        result
      end

      def strong_rtl?(cp)
        s = bidi_strong(cp)
        s == BidiStrong::R || s == BidiStrong::AL
      end

      def strong_ltr?(cp)
        bidi_strong(cp) == BidiStrong::L
      end

      # ── CompositionExclusions.txt ──────────────────────────────────────────

      def composition_exclusions
        @composition_exclusions ||= parse_composition_exclusions
      end

      def parse_composition_exclusions
        out = {}
        UnicodeRuby.read_data("CompositionExclusions.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          cp = parse_hex(stripped)
          out[cp] = true unless cp.nil?
        end
        out
      end

      # ── Composition table (inverse canonical decomposition) ────────────────

      def composition_table
        @composition_table ||= build_composition_table
      end

      def build_composition_table
        exclusions = composition_exclusions
        out = {}
        ucd_table.each do |cp, entry|
          decomp = entry[:canonical]
          next if decomp.nil? || decomp.length != 2
          next if exclusions.key?(cp)
          next unless ccc(decomp[0]) == 0

          out[[decomp[0], decomp[1]]] = cp
        end
        out
      end

      # ── Hangul algorithmic decomposition + composition ─────────────────────

      HANGUL_S_BASE = 0xAC00
      HANGUL_L_BASE = 0x1100
      HANGUL_V_BASE = 0x1161
      HANGUL_T_BASE = 0x11A7
      HANGUL_L_COUNT = 19
      HANGUL_V_COUNT = 21
      HANGUL_T_COUNT = 28
      HANGUL_N_COUNT = HANGUL_V_COUNT * HANGUL_T_COUNT
      HANGUL_S_COUNT = HANGUL_L_COUNT * HANGUL_N_COUNT

      def hangul_decompose(cp, out)
        return false if cp < HANGUL_S_BASE || cp >= HANGUL_S_BASE + HANGUL_S_COUNT

        s_index = cp - HANGUL_S_BASE
        l = HANGUL_L_BASE + (s_index / HANGUL_N_COUNT)
        v = HANGUL_V_BASE + ((s_index % HANGUL_N_COUNT) / HANGUL_T_COUNT)
        t_index = s_index % HANGUL_T_COUNT
        out << l
        out << v
        out << (HANGUL_T_BASE + t_index) unless t_index.zero?
        true
      end

      def hangul_compose(a, b)
        if a >= HANGUL_L_BASE && a < HANGUL_L_BASE + HANGUL_L_COUNT &&
           b >= HANGUL_V_BASE && b < HANGUL_V_BASE + HANGUL_V_COUNT
          l_index = a - HANGUL_L_BASE
          v_index = b - HANGUL_V_BASE
          return HANGUL_S_BASE + (((l_index * HANGUL_V_COUNT) + v_index) * HANGUL_T_COUNT)
        end
        if a >= HANGUL_S_BASE && a < HANGUL_S_BASE + HANGUL_S_COUNT &&
           ((a - HANGUL_S_BASE) % HANGUL_T_COUNT).zero? &&
           b > HANGUL_T_BASE && b < HANGUL_T_BASE + HANGUL_T_COUNT
          return a + (b - HANGUL_T_BASE)
        end
        nil
      end

      # ── Full canonical decomposition ───────────────────────────────────────

      def decompose_one(cp, out)
        return if hangul_decompose(cp, out)

        entry = ucd_table[cp]
        if entry && entry[:canonical]
          entry[:canonical].each { |child| decompose_one(child, out) }
          return
        end
        out << cp
      end

      def canonical_decompose(input)
        out = []
        input.each { |cp| decompose_one(cp, out) }
        out
      end

      # ── Canonical reordering (stable sort by CCC within non-starter runs) ──

      def canonical_reorder(seq)
        n = seq.length
        i = 0
        while i < n
          if ccc(seq[i]) == 0
            i += 1
            next
          end
          j = i
          j += 1 while j < n && ccc(seq[j]) != 0
          run = seq[i...j]
          # Stable sort by CCC — tie-break on original index to preserve order.
          sorted = run.each_with_index.sort_by { |cp, idx| [ccc(cp), idx] }.map { |cp, _idx| cp }
          seq[i...j] = sorted
          i = j
        end
        seq
      end

      # ── Canonical composition ──────────────────────────────────────────────

      def canonical_compose(seq)
        return [] if seq.empty?

        comp = composition_table
        out = []
        starter_idx = nil
        last_ccc = -1

        seq.each do |cp|
          cp_ccc = ccc(cp)

          unless starter_idx.nil?
            starter = out[starter_idx]
            composed = hangul_compose(starter, cp)
            composed = comp[[starter, cp]] if composed.nil?

            blocked = last_ccc != 0 && (cp_ccc == 0 || last_ccc >= cp_ccc)

            if !blocked && !composed.nil?
              out[starter_idx] = composed
              next
            end
          end

          out << cp
          if cp_ccc == 0
            starter_idx = out.length - 1
            last_ccc = 0
          else
            last_ccc = cp_ccc
          end
        end

        out
      end

      def to_nfc(input)
        nfd = canonical_decompose(input)
        canonical_reorder(nfd)
        canonical_compose(nfd)
      end

      def to_nfd(input)
        seq = canonical_decompose(input)
        canonical_reorder(seq)
        seq
      end

      # ── Full compatibility decomposition (NFKD/NFKC) ───────────────────────

      def compat_decompose_one(cp, out)
        return if hangul_decompose(cp, out)

        entry = ucd_table[cp]
        if entry
          if entry[:compat]
            entry[:compat].each { |child| compat_decompose_one(child, out) }
            return
          end
          if entry[:canonical]
            entry[:canonical].each { |child| compat_decompose_one(child, out) }
            return
          end
        end
        out << cp
      end

      def compat_decompose(input)
        out = []
        input.each { |cp| compat_decompose_one(cp, out) }
        out
      end

      def to_nfkd(input)
        seq = compat_decompose(input)
        canonical_reorder(seq)
        seq
      end

      def to_nfkc(input)
        nfkd = to_nfkd(input)
        canonical_compose(nfkd)
      end

      # ── CaseFolding.txt — default full case folding ────────────────────────

      def case_folding_table
        @case_folding_table ||= parse_case_folding
      end

      def parse_case_folding
        out = {}
        UnicodeRuby.read_data("CaseFolding.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          parts = stripped.split(";").map(&:strip)
          next if parts.length < 3

          status = parts[1]
          next if status != "C" && status != "F"

          src = parse_hex(parts[0])
          next if src.nil?

          tgt = parts[2].split(/\s+/).map { |t| parse_hex(t) }.compact
          next if tgt.empty?

          out[src] = tgt
        end
        out
      end

      def case_fold(input)
        table = case_folding_table
        out = []
        input.each do |cp|
          rep = table[cp]
          if rep
            out.concat(rep)
          else
            out << cp
          end
        end
        out
      end

      # ── Scripts.txt — codepoint → primary script ───────────────────────────

      def scripts_table
        @scripts_table ||= parse_scripts
      end

      def parse_scripts
        out = []
        UnicodeRuby.read_data("Scripts.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          parts = stripped.split(";", 2)
          next if parts.length < 2

          range = parse_range_field(parts[0])
          next if range.nil?

          out << [range[0], range[1], parts[1].strip]
        end
        out.sort_by! { |entry| entry[0] }
        out
      end

      def script_of(cp)
        table = scripts_table
        idx = partition_point(table) { |r| r[0] <= cp }
        if idx > 0
          entry = table[idx - 1]
          return entry[2] if cp <= entry[1]
        end
        "Unknown"
      end

      # ── ScriptExtensions.txt — codepoint → list of scripts (abbrev) ────────

      def script_extensions_table
        @script_extensions_table ||= parse_script_extensions
      end

      def parse_script_extensions
        out = []
        UnicodeRuby.read_data("ScriptExtensions.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          parts = stripped.split(";", 2)
          next if parts.length < 2

          range = parse_range_field(parts[0])
          next if range.nil?

          value = parts[1].strip.split(/\s+/)
          out << [range[0], range[1], value] unless value.empty?
        end
        out.sort_by! { |entry| entry[0] }
        out
      end

      def resolve_scripts(cp)
        table = script_extensions_table
        idx = partition_point(table) { |r| r[0] <= cp }
        if idx > 0
          entry = table[idx - 1]
          return entry[2].dup if cp <= entry[1]
        end
        primary = script_of(cp)
        abbrev = script_long_to_abbrev(primary)
        script_extension_abbrevs.key?(abbrev) ? [abbrev] : []
      end

      # The abbreviations the resolver can name: those occurring in
      # ScriptExtensions.txt. Unicode/ResolvedScripts.lean models the same set
      # as its ScriptAbbrev enum, which is why its scriptToAbbrev is partial
      # over Script. A codepoint whose primary script falls outside this set
      # resolves to no abbreviation on both sides; returning a singleton
      # instead would make every unknown-script codepoint look Single-Script,
      # putting restriction_level one rung too strict and hiding
      # RestrictionLow.
      def script_extension_abbrevs
        @script_extension_abbrevs ||=
          script_extensions_table
            .flat_map { |row| row[2] }
            .each_with_object({}) { |abbrev, seen| seen[abbrev] = true }
      end

      # ── PropertyValueAliases.txt — script long name → 4-letter abbreviation ─

      def script_name_to_abbrev
        @script_name_to_abbrev ||= parse_script_name_to_abbrev
      end

      def parse_script_name_to_abbrev
        out = {}
        UnicodeRuby.read_data("PropertyValueAliases.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          parts = stripped.split(";").map(&:strip)
          next if parts.length < 3
          next if parts[0] != "sc"

          out[parts[2]] = parts[1]
        end
        out
      end

      def script_long_to_abbrev(name)
        short = script_name_to_abbrev[name]
        if short.nil?
          raise "script_long_to_abbrev: '#{name}' not in PropertyValueAliases.txt"
        end

        short
      end

      def common_script?(cp)
        script_of(cp) == "Common"
      end

      def inherited_script?(cp)
        script_of(cp) == "Inherited"
      end

      def ignored_for_intersection?(cp)
        common_script?(cp) || inherited_script?(cp)
      end

      # Union of all resolved scripts across non-Common, non-Inherited
      # codepoints of `input`.
      def string_script_union(input)
        acc = []
        input.each do |cp|
          next if ignored_for_intersection?(cp)

          resolve_scripts(cp).each do |s|
            acc << s unless acc.include?(s)
          end
        end
        acc
      end

      # ── IdentifierStatus.txt — UTS #39 Allowed set ─────────────────────────

      def identifier_allowed_ranges
        @identifier_allowed_ranges ||= parse_identifier_status
      end

      def parse_identifier_status
        out = []
        UnicodeRuby.read_data("IdentifierStatus.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          parts = stripped.split(";", 2)
          next if parts.length < 2
          next if parts[1].strip != "Allowed"

          range = parse_range_field(parts[0])
          out << range if range
        end
        out.sort_by! { |entry| entry[0] }
        out
      end

      def id_allowed?(cp)
        table = identifier_allowed_ranges
        idx = partition_point(table) { |r| r[0] <= cp }
        if idx > 0
          entry = table[idx - 1]
          return true if cp <= entry[1]
        end
        false
      end

      # ── DerivedCoreProperties.txt — Default_Ignorable_Code_Point ranges ────

      def default_ignorable_ranges
        @default_ignorable_ranges ||= parse_default_ignorable
      end

      def parse_default_ignorable
        out = []
        UnicodeRuby.read_data("DerivedCoreProperties.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          parts = stripped.split(";", 2)
          next if parts.length < 2
          next if parts[1].strip != "Default_Ignorable_Code_Point"

          range = parse_range_field(parts[0])
          out << range if range
        end
        out.sort_by! { |entry| entry[0] }
        out
      end

      def default_ignorable?(cp)
        table = default_ignorable_ranges
        idx = partition_point(table) { |r| r[0] <= cp }
        if idx > 0
          entry = table[idx - 1]
          return true if cp <= entry[1]
        end
        false
      end

      # True iff `cp` is a White_Space codepoint per UCD PropList.txt.
      def white_space?(cp)
        (cp >= 0x0009 && cp <= 0x000D) ||
          cp == 0x0020 ||
          cp == 0x0085 ||
          cp == 0x00A0 ||
          cp == 0x1680 ||
          (cp >= 0x2000 && cp <= 0x200A) ||
          (cp >= 0x2028 && cp <= 0x2029) ||
          cp == 0x202F ||
          cp == 0x205F ||
          cp == 0x3000
      end

      # ── UTS #39 §5.1 Restriction-level classification ──────────────────────

      def ascii_only?(cps)
        cps.all? { |cp| cp < 0x80 }
      end

      def intersect_many(sets)
        return [] if sets.empty?

        acc = sets[0].dup
        sets[1..].each do |s|
          acc = acc.select { |x| s.include?(x) }
        end
        acc
      end

      def string_resolved_scripts(cps)
        non_ignored = cps.reject { |cp| ignored_for_intersection?(cp) }
        return [] if non_ignored.empty?

        sets = non_ignored.map { |cp| resolve_scripts(cp) }
        intersect_many(sets)
      end

      def single_script?(cps)
        !ascii_only?(cps) && !string_resolved_scripts(cps).empty?
      end

      COVERED_JAPANESE = %w[Latn Hani Hira Kana].freeze
      COVERED_CHINESE = %w[Latn Hani Bopo].freeze
      COVERED_KOREAN = %w[Latn Hani Hang].freeze

      def intersects?(a, b)
        a.any? { |x| b.include?(x) }
      end

      def all_within_covered?(cps, covered)
        cps.all? do |cp|
          next true if ignored_for_intersection?(cp)

          r = resolve_scripts(cp)
          !r.empty? && intersects?(r, covered)
        end
      end

      def covered_cjk?(cps)
        all_within_covered?(cps, COVERED_JAPANESE) ||
          all_within_covered?(cps, COVERED_CHINESE) ||
          all_within_covered?(cps, COVERED_KOREAN)
      end

      def highly_restrictive?(cps)
        single_script?(cps) || covered_cjk?(cps)
      end

      def moderately_restrictive_shape?(cps)
        other = nil
        cps.each do |cp|
          next if ignored_for_intersection?(cp)

          r = resolve_scripts(cp)
          return false if r.empty?
          next if r.include?("Latn")

          s = r[0]
          return false if s == "Cyrl" || s == "Grek"

          if other.nil?
            other = s
          elsif s != other
            return false
          end
        end
        !other.nil?
      end

      def minimally_restrictive?(cps)
        cps.all? { |cp| id_allowed?(cp) }
      end

      def restriction_level(cps)
        if ascii_only?(cps)
          RestrictionLevel::ASCII_ONLY
        elsif single_script?(cps)
          RestrictionLevel::SINGLE_SCRIPT
        elsif highly_restrictive?(cps)
          RestrictionLevel::HIGHLY_RESTRICTIVE
        elsif moderately_restrictive_shape?(cps)
          RestrictionLevel::MODERATELY_RESTRICTIVE
        elsif minimally_restrictive?(cps)
          RestrictionLevel::MINIMALLY_RESTRICTIVE
        else
          RestrictionLevel::UNRESTRICTED
        end
      end

      # ── UAX #21 case mapping (to_lower) from SpecialCasing.txt + UnicodeData ─

      # Each SpecialCasing row: { lower: Array, upper: Array,
      # conditions: Array<String> }.  A row is `code; lower; title; upper;
      # conditions`; the lowercase mapping is field 1 (0-based) and the
      # uppercase mapping is field 3.
      def special_casing_rows
        @special_casing_rows ||= parse_special_casing
      end

      def parse_special_casing
        rows = {}
        UnicodeRuby.read_data("SpecialCasing.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          fields = stripped.split(";").map(&:strip)
          next if fields.length < 4

          code = parse_hex(fields[0])
          next if code.nil?

          conditions =
            if fields.length > 4 && !fields[4].empty?
              fields[4].split(/\s+/)
            else
              []
            end

          (rows[code] ||= []) << {
            lower: fields[1].split(/\s+/).map { |t| parse_hex(t) }.compact,
            upper: fields[3].split(/\s+/).map { |t| parse_hex(t) }.compact,
            conditions: conditions
          }
        end
        rows
      end

      def simple_lowercase_table
        @simple_lowercase_table ||= parse_simple_lowercase
      end

      def parse_simple_lowercase
        lower = {}
        UnicodeRuby.read_data("UnicodeData.txt").each_line do |raw|
          fields = raw.chomp.split(";", -1)
          next if fields.length < 15

          cp = parse_hex(fields[0])
          next if cp.nil?
          next if fields[13].empty?

          l = parse_hex(fields[13])
          lower[cp] = l unless l.nil?
        end
        lower
      end

      def simple_lowercase(cp)
        simple_lowercase_table.fetch(cp, cp)
      end

      def simple_uppercase_table
        @simple_uppercase_table ||= parse_simple_uppercase
      end

      # Simple uppercase mapping from UnicodeData.txt field 12 (0-based; the
      # simple uppercase mapping), mirroring the simple-lowercase parse of
      # field 13.
      def parse_simple_uppercase
        upper = {}
        UnicodeRuby.read_data("UnicodeData.txt").each_line do |raw|
          fields = raw.chomp.split(";", -1)
          next if fields.length < 15

          cp = parse_hex(fields[0])
          next if cp.nil?
          next if fields[12].empty?

          u = parse_hex(fields[12])
          upper[cp] = u unless u.nil?
        end
        upper
      end

      def simple_uppercase(cp)
        simple_uppercase_table.fetch(cp, cp)
      end

      def casing_property_ranges(name)
        out = []
        UnicodeRuby.read_data("DerivedCoreProperties.txt").each_line do |raw|
          stripped = strip_comment_and_trim(raw.chomp)
          next if stripped.empty?

          parts = stripped.split(";", 2)
          next if parts.length < 2 || parts[1].strip != name

          range = parse_range_field(parts[0])
          out << range if range
        end
        out
      end

      def cased_ranges
        @cased_ranges ||= casing_property_ranges("Cased")
      end

      def soft_dotted_ranges
        @soft_dotted_ranges ||= casing_property_ranges("Soft_Dotted")
      end

      def in_ranges?(ranges, cp)
        ranges.any? { |lo, hi| lo <= cp && cp <= hi }
      end

      def cased?(cp)
        in_ranges?(cased_ranges, cp)
      end

      def soft_dotted?(cp)
        in_ranges?(soft_dotted_ranges, cp)
      end

      # ── UAX #31 default identifier + UTS #39 whole-string admissibility ─────
      #
      # XID_Start / XID_Continue are read from DerivedCoreProperties.txt via the
      # same `casing_property_ranges` parser that yields Cased / Soft_Dotted, so
      # this is the real derived-core-property predicate, not a heuristic.
      # `id_allowed?` (above) supplies the per-codepoint UTS #39
      # Identifier_Status = Allowed test.

      def xid_start_ranges
        @xid_start_ranges ||= casing_property_ranges("XID_Start")
      end

      def xid_continue_ranges
        @xid_continue_ranges ||= casing_property_ranges("XID_Continue")
      end

      def xid_start?(cp)
        in_ranges?(xid_start_ranges, cp)
      end

      def xid_continue?(cp)
        in_ranges?(xid_continue_ranges, cp)
      end

      # UAX #31 default identifier start: XID_Start or U+005F LOW LINE.
      def default_id_start?(cp)
        xid_start?(cp) || cp == 0x005F
      end

      # UAX #31 default identifier continue: XID_Continue.
      def default_id_continue?(cp)
        xid_continue?(cp)
      end

      # True iff `cps` is a well-formed UAX #31 default identifier: a non-empty
      # sequence whose first codepoint is a default-id start and whose remaining
      # codepoints are default-id continues.
      def default_identifier?(cps)
        return false if cps.empty?

        default_id_start?(cps[0]) && cps[1..].all? { |cp| default_id_continue?(cp) }
      end

      # True iff `cps` is a well-formed default identifier AND every codepoint
      # has Identifier_Status = Allowed per UTS #39 — the whole-string
      # admissibility predicate `isAllowedIdentifier`.
      def allowed_identifier?(cps)
        default_identifier?(cps) && cps.all? { |cp| id_allowed?(cp) }
      end

      # Context predicates (UAX #21).  `rev_prefix` is the preceding codepoints
      # nearest-first; `suffix` the strictly-following ones.

      def more_above_after(suffix)
        suffix.each do |cp|
          c = ccc(cp)
          return true if c == 230
          return false if c == 0
        end
        false
      end

      def after_soft_dotted(rev_prefix)
        rev_prefix.each do |cp|
          return true if soft_dotted?(cp)

          c = ccc(cp)
          return false if c == 0 || c == 230
        end
        false
      end

      def after_i(rev_prefix)
        rev_prefix.each do |cp|
          return true if cp == 0x0049

          c = ccc(cp)
          return false if c == 0 || c == 230
        end
        false
      end

      def before_dot(suffix)
        suffix.each do |cp|
          return true if cp == 0x0307
          return false if ccc(cp) == 0
        end
        false
      end

      def has_cased_before(rev_prefix)
        rev_prefix.each do |cp|
          return true if cased?(cp)
          return false if ccc(cp) == 0
        end
        false
      end

      def has_cased_after(suffix)
        suffix.each do |cp|
          return true if cased?(cp)
          return false if ccc(cp) == 0
        end
        false
      end

      def final_sigma(rev_prefix, suffix)
        has_cased_before(rev_prefix) && !has_cased_after(suffix)
      end

      def locale_condition?(condition)
        condition == "tr" || condition == "az" || condition == "lt"
      end

      def locale_matches(locale, conditions)
        return true unless conditions.any? { |c| locale_condition?(c) }

        conditions.any? do |c|
          (c == "tr" && locale == Locale::TURKISH) ||
            (c == "az" && locale == Locale::AZERI) ||
            (c == "lt" && locale == Locale::LITHUANIAN)
        end
      end

      def conditions_hold(locale, rev_prefix, suffix, conditions)
        return false unless locale_matches(locale, conditions)

        conditions.each do |c|
          next if locale_condition?(c)

          ok =
            case c
            when "Final_Sigma" then final_sigma(rev_prefix, suffix)
            when "Not_Final_Sigma" then !final_sigma(rev_prefix, suffix)
            when "After_Soft_Dotted" then after_soft_dotted(rev_prefix)
            when "More_Above" then more_above_after(suffix)
            when "Not_Before_Dot" then !before_dot(suffix)
            when "After_I" then after_i(rev_prefix)
            else false
            end
          return false unless ok
        end
        true
      end

      def find_special_row(locale, rev_prefix, suffix, cp)
        candidates = special_casing_rows[cp]
        return nil if candidates.nil?

        candidates.each do |row|
          if !row[:conditions].empty? &&
             conditions_hold(locale, rev_prefix, suffix, row[:conditions])
            return row
          end
        end
        candidates.find { |row| row[:conditions].empty? }
      end

      # Lowercase a single codepoint in its full input context (UAX #21).
      def lower_codepoint(locale, rev_prefix, suffix, cp)
        row = find_special_row(locale, rev_prefix, suffix, cp)
        if row
          row[:lower].dup
        else
          [simple_lowercase(cp)]
        end
      end

      # Uppercase a single codepoint in its full input context (UAX #21): the
      # SpecialCasing row whose conditions hold (its uppercase column), else the
      # simple uppercase mapping.  Mirrors `lower_codepoint` exactly, reusing the
      # same context machinery (`find_special_row` / `conditions_hold`).
      def upper_codepoint(locale, rev_prefix, suffix, cp)
        row = find_special_row(locale, rev_prefix, suffix, cp)
        if row
          row[:upper].dup
        else
          [simple_uppercase(cp)]
        end
      end

      # Lowercase a codepoint sequence under `locale` (UAX #21 full case
      # mapping).  Computed from the pinned UCD tables, not the runtime.
      def to_lower(locale, cps)
        out = []
        rev_prefix = []
        cps.each_with_index do |cp, index|
          suffix = cps[(index + 1)..]
          out.concat(lower_codepoint(locale, rev_prefix, suffix, cp))
          rev_prefix.unshift(cp)
        end
        out
      end
    end
  end
end
