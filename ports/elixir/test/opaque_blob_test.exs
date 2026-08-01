defmodule UnicodeSecurity.OpaqueBlobTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.OpaqueBlob
  alias UnicodeSecurity.OpaqueBlob.Utf8Blob
  alias UnicodeSecurity.ValidatedUtf8

  test "opaque-blob predicate accepts valid utf-8" do
    assert OpaqueBlob.utf8_blob?(<<0x48, 0x69>>)
    assert OpaqueBlob.utf8_blob?(<<0xC3, 0xA9>>)
    assert OpaqueBlob.utf8_blob?(<<0xF0, 0x9F, 0x98, 0x80>>)
  end

  test "opaque-blob predicate rejects invalid utf-8" do
    refute OpaqueBlob.utf8_blob?(<<0xC0, 0x80>>)
    refute OpaqueBlob.utf8_blob?(<<0xED, 0xA0, 0x80>>)
  end

  test "refinement builds within bound and rejects otherwise" do
    assert %Utf8Blob{value: <<0x48, 0x69>>, max_bytes: 16} = OpaqueBlob.of(<<0x48, 0x69>>, 16)
    assert OpaqueBlob.of(<<0x48, 0x69, 0x21>>, 2) == nil
    assert OpaqueBlob.of(<<0xC0, 0x80>>, 16) == nil
    assert %Utf8Blob{} = OpaqueBlob.of(<<>>, 32)
  end

  test "validated utf-8 validate, borrow, and unwrap" do
    validated = ValidatedUtf8.validate(<<0xC3, 0xA9>>)
    assert %ValidatedUtf8{} = validated
    assert ValidatedUtf8.as_bytes(validated) == <<0xC3, 0xA9>>
    assert ValidatedUtf8.unwrap(validated) == <<0xC3, 0xA9>>
    assert ValidatedUtf8.validate(<<0xED, 0xA0, 0x80>>) == nil
  end
end
