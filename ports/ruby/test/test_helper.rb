# frozen_string_literal: true

require "json"
require "minitest/autorun"

require_relative "../lib/unicode_ruby"

PORT_ROOT = File.expand_path("..", __dir__)

module RubyPortTestHelpers
  Policy = UnicodeRuby::Security::Policy

  PROFILES = {
    "gateway-header" => Policy::Profile::GATEWAY_HEADER,
    "domain-name" => Policy::Profile::DOMAIN_NAME,
    "dns-label" => Policy::Profile::DNS_LABEL,
    "url" => Policy::Profile::URL,
    "username" => Policy::Profile::USERNAME,
    "display-name" => Policy::Profile::DISPLAY_NAME,
    "chat-message" => Policy::Profile::CHAT_MESSAGE,
    "source-code" => Policy::Profile::SOURCE_CODE,
    "opaque-secret" => Policy::Profile::OPAQUE_SECRET,
    "binary-blob" => Policy::Profile::BINARY_BLOB
  }.freeze

  MODES = {
    "observe" => Policy::Mode::OBSERVE,
    "warn" => Policy::Mode::WARN,
    "enforce" => Policy::Mode::ENFORCE,
    "strict" => Policy::Mode::STRICT
  }.freeze

  def fixture_json(*parts)
    JSON.parse(File.read(File.join(PORT_ROOT, "testdata", "fixtures", "security", *parts), encoding: "UTF-8"))
  end

  def profile(tag)
    PROFILES.fetch(tag)
  end

  def mode(tag)
    MODES.fetch(tag)
  end

  def scan_encoded_case(case_data)
    scanner = {
      "utf-8" => :scan_utf8,
      "utf-16be" => :scan_utf16be,
      "utf-16le" => :scan_utf16le,
      "utf-32be" => :scan_utf32be,
      "utf-32le" => :scan_utf32le
    }.fetch(case_data.fetch("encoding"))

    Policy.public_send(
      scanner,
      profile(case_data.fetch("profile")),
      mode(case_data.fetch("mode")),
      case_data.fetch("input_bytes")
    )
  end
end
