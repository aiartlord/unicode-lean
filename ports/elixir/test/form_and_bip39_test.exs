defmodule UnicodeSecurity.FormAndBip39Test do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Crypto.Bip39Canonical
  alias UnicodeSecurity.Form.{LocaleCaseInversion, NfcIdempotenceWitness, NormalizationBomb}

  test "form detectors" do
    assert LocaleCaseInversion.detect([]).sub == nil
    assert LocaleCaseInversion.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).sub == nil
    assert LocaleCaseInversion.detect([0x0049]).sub == "TurkishCaseDivergence"
    assert LocaleCaseInversion.detect([0x0049]).positions == [0]
    assert LocaleCaseInversion.detect([0x0130]).sub == "TurkishCaseDivergence"
    assert LocaleCaseInversion.detect([0x0049, 0x0300]).sub == "TurkishCaseDivergence"
    assert LocaleCaseInversion.detect([0x004A, 0x0300]).sub == "LithuanianCaseDivergence"

    assert NfcIdempotenceWitness.detect([]).sub == nil
    assert NfcIdempotenceWitness.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).sub == nil
    assert NfcIdempotenceWitness.detect([0x00E9]).sub == nil
    assert NfcIdempotenceWitness.detect([0x0065, 0x0301]).sub == "NonNfcForm"
    assert NfcIdempotenceWitness.detect([0x0065, 0x0301]).positions == [0]
    assert NfcIdempotenceWitness.detect([0xFB01]).sub == "NonNfkcCompatForm"

    assert NormalizationBomb.detect([]).sub == nil
    assert NormalizationBomb.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).sub == nil
    assert NormalizationBomb.detect([0xD55C]).sub == nil
    assert NormalizationBomb.detect([0x2460]).sub == nil
    assert NormalizationBomb.detect([0xFDFA]).sub == "SingleCpBlowup"
    assert NormalizationBomb.detect([0xFDFA]).positions == [0]
    assert NormalizationBomb.detect([0xFDFB]).sub == "NfkdHighExpansion"
    assert NormalizationBomb.detect([0x1F82]).sub == "NfdHighExpansion"
  end

  test "bip39 canonical detector" do
    abandon = ~c"abandon"
    about = ~c"about"
    assert Bip39Canonical.bip39_canonical(~c"a  b") == ~c"a b"
    assert Bip39Canonical.bip39_canonical(~c"A") == ~c"a"
    assert Bip39Canonical.detect(abandon ++ [0x20]).sub == "TrailingWhitespace"
    assert Bip39Canonical.detect(~c"Abandon").sub == "MixedCase"
    assert Bip39Canonical.detect(abandon ++ [0x20, 0x20] ++ about).sub == "WhitespaceAnomaly"
    assert Bip39Canonical.detect([0xFB00]).sub == "NonNFKD"
    assert Bip39Canonical.detect(~c"qzqz").sub == "WordlistMismatch"

    mnemonic = List.duplicate(abandon ++ [0x20], 11) |> List.flatten() |> Kernel.++(about)
    verdict = Bip39Canonical.detect(mnemonic)
    assert verdict.sub == nil
    assert verdict.language == "english"
    assert verdict.word_count == 12
  end
end
