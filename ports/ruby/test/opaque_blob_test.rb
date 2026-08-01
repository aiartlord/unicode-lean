# frozen_string_literal: true

require_relative "test_helper"

# Utf8Blob / ValidatedUtf8 refinement-type tests. Byte sequences are byte
# arrays (Array<Integer>) in this port.
class OpaqueBlobTest < Minitest::Test
  OpaqueBlob = UnicodeRuby::OpaqueBlob
  Utf8Blob = UnicodeRuby::Utf8Blob
  ValidatedUtf8 = UnicodeRuby::ValidatedUtf8
  ValidatedUtf8Ops = UnicodeRuby::ValidatedUtf8Ops

  def test_accepts_valid_utf8
    assert OpaqueBlob.utf8_blob?([0x48, 0x69])
    assert OpaqueBlob.utf8_blob?([0xC3, 0xA9])
    assert OpaqueBlob.utf8_blob?([0xF0, 0x9F, 0x98, 0x80])
  end

  def test_rejects_invalid_utf8
    refute OpaqueBlob.utf8_blob?([0xC0, 0x80])
    refute OpaqueBlob.utf8_blob?([0xED, 0xA0, 0x80])
  end

  def test_refinement_builds_within_bound
    blob = Utf8Blob.of([0x48, 0x69], 16)
    refute_nil blob
    assert_equal [0x48, 0x69], blob.value
    assert_equal 16, blob.max_bytes
  end

  def test_refinement_rejects_over_bound
    assert_nil Utf8Blob.of([0x48, 0x69, 0x21], 2)
  end

  def test_refinement_rejects_malformed_utf8
    assert_nil Utf8Blob.of([0xC0, 0x80], 16)
  end

  def test_refinement_accepts_empty_under_any_bound
    refute_nil Utf8Blob.of([], 32)
  end

  def test_validated_utf8_validate_and_unwrap
    validated = ValidatedUtf8.validate([0xC3, 0xA9])
    refute_nil validated
    assert_equal [0xC3, 0xA9], validated.as_bytes
    assert_equal [0xC3, 0xA9], ValidatedUtf8Ops.unwrap(validated)
  end

  def test_validated_utf8_rejects_malformed
    assert_nil ValidatedUtf8.validate([0xED, 0xA0, 0x80])
  end
end
