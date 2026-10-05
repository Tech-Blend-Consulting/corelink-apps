# frozen_string_literal: true

require 'base64'
require 'json'
require 'openssl'
require 'uri'

module TransitClient
  # Opening a sealed envelope.
  #
  # The application takes ciphertext from a connector and the key from CoreLink,
  # and opens the secret itself. Nothing between the two holds both halves: the
  # connector is granted secrets:cache and keeps envelopes it has no authority to
  # open, and the application is granted secrets:unwrap and may open one it
  # already has.
  #
  # The additional authenticated data is rebuilt here from the secret id and
  # version and required to equal the value stored on the envelope. Decrypting
  # with whatever the envelope carries would detect an altered envelope, because
  # the tag breaks, but would bind nothing -- an envelope claiming to be some
  # other secret would open happily.
  #
  # See docs/secret-delivery.md.
  module Sealed
    # Prefix of the additional authenticated data. Must match crypto.SecretAAD on
    # the platform byte for byte: the two are one wire format, and changing either
    # alone stops every envelope opening. Pinned by
    # sdk/testdata/sealed_envelope.json, which the platform produces.
    AAD_PREFIX = 'cl.secret.v1'

    # AES-GCM's tag, which Go appends to the ciphertext and OpenSSL wants
    # separately.
    TAG_BYTES = 16

    # Needs a Ruby whose openssl can set additional authenticated data.
    #
    # macOS system Ruby (2.6, openssl gem 2.1.2, LibreSSL) cannot: auth_data=
    # raises "couldn't set additional authenticated data" whatever order it is
    # called in, and auth_tag_len= segfaults the interpreter. Measured, not
    # assumed. A secret cannot be opened without the AAD, so there is no
    # fallback to offer -- the answer is a Ruby built against OpenSSL, which is
    # what the gemspec now requires.

    # A cached envelope the current key will not open.
    #
    # Separate from CorruptEnvelope because the recoveries differ: ask the
    # connector for a fresh envelope. A rollback attempt and a damaged envelope
    # look identical at the AEAD and should not look identical in a log.
    class StaleEnvelope < StandardError; end

    # An envelope that did not open and was not stale.
    #
    # The key belonged to the version the envelope claims and it still failed, so
    # the ciphertext or the tag has been altered. Refetching will not help.
    class CorruptEnvelope < StandardError; end

    # A connector answered with a different secret than the one asked for.
    #
    # The case the AAD does not cover. An envelope is bound to its own id and
    # version, so another secret's id and envelope together are internally
    # consistent and open cleanly -- under the wrong name. A compromised
    # connector can therefore answer a request for one secret with another the
    # application also holds unwrap on, and every cryptographic check passes.
    #
    # CoreLink returns the name the id really belongs to, and the application
    # knows the name it asked for; neither alone can see the substitution, so
    # the comparison happens in the client.
    class WrongSecret < StandardError; end

    class << self
      # The additional authenticated data for a secret and version.
      def secret_aad(secret_id, version)
        "#{AAD_PREFIX}|#{secret_id}|#{version}"
      end

      # Open a sealed envelope and return the plaintext.
      #
      # +dek+ is the key CoreLink returned for this secret. +secret_id+ and
      # +version+ are the authorized context the AAD is rebuilt from, not values
      # read out of the envelope.
      def open_envelope(envelope_b64, dek, secret_id, version)
        begin
          body = JSON.parse(Base64.strict_decode64(envelope_b64))
        rescue ArgumentError, JSON::ParserError => e
          raise CorruptEnvelope, "the envelope is not an envelope: #{e.message}"
        end

        expected = secret_aad(secret_id, version)
        stored = body['aad']
        # An envelope carrying no AAD was written before binding existed, and
        # opens with none. That is not a rollback -- the thing this must never be
        # confused with -- and the platform skips its own compare for these too.
        # Setting the expected value here instead would break every secret
        # written before the binding did, which is all of them at a given
        # installation until the first rotation.
        unbound = stored.nil? || stored.empty?
        if stored && !stored.empty? && Base64.decode64(stored) != expected
          # Sealed for a different secret or version. Named as stale rather than
          # corrupt: the likely cause is a connector holding an old envelope, and
          # the recovery is to ask it again.
          raise StaleEnvelope,
                "the envelope is bound to something other than #{secret_id} version #{version}"
        end

        raise CorruptEnvelope, 'the envelope is missing its ciphertext' unless body['encrypted_data'] && body['nonce']

        sealed = Base64.decode64(body['encrypted_data'])
        nonce = Base64.decode64(body['nonce'])
        raise CorruptEnvelope, 'the envelope carries no ciphertext' if sealed.bytesize <= TAG_BYTES

        # Go appends the tag; OpenSSL takes it separately.
        ciphertext = sealed[0...(sealed.bytesize - TAG_BYTES)]
        tag = sealed[(sealed.bytesize - TAG_BYTES)..]

        begin
          cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
          cipher.key = dek
          cipher.iv = nonce
          cipher.auth_tag = tag
          cipher.auth_data = expected unless unbound
          cipher.update(ciphertext) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          # The key was for the version the envelope claims and the binding
          # matched, so this is not a rollback: something has been altered.
          raise CorruptEnvelope, 'the envelope did not open with the key for its own version'
        end
      end

      # The secret's value from a stored record.
      #
      # What is sealed is the record, which wraps the value. Older records may be
      # the bare value, so that is the fallback rather than an error.
      def value_from(plaintext)
        record = JSON.parse(plaintext)
        return record['value'] if record.is_a?(Hash) && record['value'] && !record['value'].empty?

        plaintext
      rescue JSON::ParserError
        plaintext
      end

      # Parse a TLS bundle out of a secret's value.
      #
      # The value is one level deeper than it looks: the stored record wraps it,
      # and for a certificate the value is itself JSON. #value_from unwraps the
      # record, and this parses what came out.
      #
      # Both halves are required. A secret that merely happens to be JSON would
      # otherwise come back as a certificate with empty fields, which is worse
      # than an error because it fails later and somewhere else.
      def certificate_from(value)
        bundle = begin
          JSON.parse(value)
        rescue JSON::ParserError => e
          raise ArgumentError, "not a TLS certificate bundle: #{e.message}"
        end
        raise ArgumentError, 'not a TLS certificate bundle' unless bundle.is_a?(Hash)

        cert = bundle['certificate'].to_s
        key = bundle['private_key'].to_s
        raise ArgumentError, 'carries no certificate and key' if cert.empty? || key.empty?

        { certificate: cert, private_key: key, ca_chain: bundle['ca_chain'].to_s }
      end

      # Escape a secret name for a URL, keeping the slashes that are part of it.
      #
      # A "." or ".." segment is refused rather than escaped. Clients and servers
      # normalise dot segments in a path, so such a name would be asked for as a
      # different one, and no secret can be named that way: the platform's own
      # path validation rejects "..".
      def envelope_path(name)
        trimmed = name.to_s.gsub(%r{\A/+|/+\z}, '')
        raise ArgumentError, 'a secret name is required' if trimmed.empty?

        parts = trimmed.split('/')
        parts.each do |part|
          raise ArgumentError, "#{name.inspect} has an empty path segment" if part.empty?
          raise ArgumentError, "#{name.inspect} is not a secret name" if ['.', '..'].include?(part)
        end
        parts.map { |p| URI.encode_www_form_component(p).gsub('+', '%20') }.join('/')
      end
    end
  end
end
