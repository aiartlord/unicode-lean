# frozen_string_literal: true

require_relative "test_helper"

class FormDetectorsTest < Minitest::Test
  LocaleCase = UnicodeRuby::Security::Form::LocaleCaseInversion
  NfcWitness = UnicodeRuby::Security::Form::NfcIdempotenceWitness
  NormalizationBomb = UnicodeRuby::Security::Form::NormalizationBomb

  def test_locale_case_inversion_contract_vectors
    assert_nil LocaleCase.detect([]).sub
    assert_nil LocaleCase.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).sub

    assert_equal "TurkishCaseDivergence", LocaleCase.detect([0x0049]).sub
    assert_equal [0], LocaleCase.detect([0x0049]).positions
    assert_equal "TurkishCaseDivergence", LocaleCase.detect([0x0130]).sub
    assert_equal "TurkishCaseDivergence", LocaleCase.detect([0x0049, 0x0300]).sub
    assert_equal "LithuanianCaseDivergence", LocaleCase.detect([0x004A, 0x0300]).sub
  end

  def test_nfc_idempotence_witness_contract_vectors
    assert_nil NfcWitness.detect([]).sub
    assert_nil NfcWitness.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).sub
    assert_nil NfcWitness.detect([0x00E9]).sub

    decomposed = NfcWitness.detect([0x0065, 0x0301])
    assert_equal "NonNfcForm", decomposed.sub
    assert_equal [0], decomposed.positions
    assert_equal "NonNfkcCompatForm", NfcWitness.detect([0xFB01]).sub
  end

  def test_normalization_bomb_contract_vectors
    assert_nil NormalizationBomb.detect([]).sub
    assert_nil NormalizationBomb.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).sub
    assert_nil NormalizationBomb.detect([0xD55C]).sub
    assert_nil NormalizationBomb.detect([0x2460]).sub

    blowup = NormalizationBomb.detect([0xFDFA])
    assert_equal "SingleCpBlowup", blowup.sub
    assert_equal [0], blowup.positions
    assert_equal "NfkdHighExpansion", NormalizationBomb.detect([0xFDFB]).sub
    assert_equal "NfdHighExpansion", NormalizationBomb.detect([0x1F82]).sub
  end
end
