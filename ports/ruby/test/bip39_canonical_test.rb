# frozen_string_literal: true

require_relative "test_helper"

class Bip39CanonicalTest < Minitest::Test
  Bip39 = UnicodeRuby::Security::Crypto::Bip39Canonical

  ABANDON = [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E].freeze
  ABOUT = [0x61, 0x62, 0x6F, 0x75, 0x74].freeze

  def test_canonicalisation_spot_checks
    assert_equal [], Bip39.bip39_canonical([])
    assert_equal [0x61, 0x20, 0x62], Bip39.bip39_canonical([0x61, 0x20, 0x20, 0x62])
    assert_equal [0x61], Bip39.bip39_canonical([0x61, 0x20])
    assert_equal [0x61], Bip39.bip39_canonical([0x20, 0x61])
    assert_equal [0x61], Bip39.bip39_canonical([0x41])
    assert_equal [0x61, 0x20, 0x62], Bip39.bip39_canonical([0x61, 0x3000, 0x62])
  end

  def test_detect_hazard_tags
    assert_equal "TrailingWhitespace", Bip39.detect(ABANDON + [0x20]).sub
    assert_equal "MixedCase", Bip39.detect([0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]).sub
    assert_equal "WhitespaceAnomaly", Bip39.detect(ABANDON + [0x20, 0x20] + ABOUT).sub
    assert_equal "WhitespaceAnomaly", Bip39.detect([0x20] + ABANDON).sub
    assert_equal "NonNFKD", Bip39.detect([0xFB00]).sub
    assert_equal "NonNFKD", Bip39.detect([0x61, 0x00A0, 0x62]).sub
    assert_equal "WordlistMismatch", Bip39.detect([0x71, 0x7A, 0x71, 0x7A]).sub
  end

  def test_detect_positions
    assert_equal [7], Bip39.detect(ABANDON + [0x20]).positions
    assert_equal [0], Bip39.detect([0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]).positions
  end

  def test_detect_clear_and_wordcount
    empty = Bip39.detect([])
    assert_nil empty.sub
    assert_equal "english", empty.language

    mnemonic = []
    11.times { mnemonic += ABANDON + [0x20] }
    mnemonic += ABOUT
    verdict = Bip39.detect(mnemonic)
    assert_nil verdict.sub
    assert_equal "english", verdict.language
    assert_equal 12, verdict.word_count
  end
end
