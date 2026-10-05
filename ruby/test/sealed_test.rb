# frozen_string_literal: true

# The sealed envelope, opened against a fixture the platform produced.
#
# The fixture comes from internal/crypto, which is what CoreLink stores and what
# the unwrap endpoint returns, so this checks agreement with the platform rather
# than agreement with itself.
#
# Regenerate: go test ./internal/crypto/ -run TestSDKFixture -update
# Run:        ruby -Isdk/ruby/lib sdk/ruby/test/sealed_test.rb

require 'base64'
require 'json'
require 'minitest/autorun'
require 'transit_client/sealed'

class SealedEnvelopeTest < Minitest::Test
  FIXTURE = File.expand_path('../../testdata/sealed_envelope.json', __dir__)

  def setup
    @fx = JSON.parse(File.read(FIXTURE))
    @dek = Base64.decode64(@fx['dek'])
  end

  def test_the_aad_matches_the_platforms
    # One wire format shared with crypto.SecretAAD. If this drifts, nothing
    # opens, so it is checked against bytes the platform wrote.
    got = TransitClient::Sealed.secret_aad(@fx['secret_id'], @fx['version'])
    assert_equal Base64.decode64(@fx['aad']), got
  end

  def test_it_opens_what_the_platform_sealed
    plaintext = TransitClient::Sealed.open_envelope(
      @fx['envelope'], @dek, @fx['secret_id'], @fx['version']
    )
    assert_equal @fx['expected_plaintext'], plaintext
    assert_equal @fx['expected_value'], TransitClient::Sealed.value_from(plaintext)
  end

  def test_the_wrong_version_does_not_open_it
    # What makes a stale cached envelope fail closed rather than being served as
    # though it were current.
    assert_raises(TransitClient::Sealed::StaleEnvelope) do
      TransitClient::Sealed.open_envelope(@fx['envelope'], @dek, @fx['secret_id'], @fx['version'] + 1)
    end
  end

  def test_a_false_secret_id_does_not_open_it
    # The case authorization cannot catch: the caller may hold unwrap on both
    # secrets, so only the binding can stop this.
    assert_raises(TransitClient::Sealed::StaleEnvelope) do
      TransitClient::Sealed.open_envelope(
        @fx['envelope'], @dek, '00000000-0000-0000-0000-000000000000', @fx['version']
      )
    end
  end

  def test_another_key_does_not_open_it
    assert_raises(TransitClient::Sealed::CorruptEnvelope) do
      TransitClient::Sealed.open_envelope(@fx['envelope'], "\0" * 32, @fx['secret_id'], @fx['version'])
    end
  end

  def test_altered_ciphertext_is_corrupt_not_stale
    # Refetching cannot repair this, so it must not be reported as something a
    # refetch would fix.
    body = JSON.parse(Base64.strict_decode64(@fx['envelope']))
    data = Base64.decode64(body['encrypted_data']).bytes
    data[0] ^= 0xff
    body['encrypted_data'] = Base64.strict_encode64(data.pack('C*'))
    altered = Base64.strict_encode64(JSON.generate(body))

    assert_raises(TransitClient::Sealed::CorruptEnvelope) do
      TransitClient::Sealed.open_envelope(altered, @dek, @fx['secret_id'], @fx['version'])
    end
  end

  def test_envelope_path_keeps_slashes_and_refuses_dot_segments
    assert_equal 'production/dbone', TransitClient::Sealed.envelope_path('production/dbone')
    assert_equal 'production/dbone', TransitClient::Sealed.envelope_path('/production/dbone/')
    assert_equal 'prod/db%20one', TransitClient::Sealed.envelope_path('prod/db one')
    ['prod/../etc/passwd', 'prod/.', '..', 'prod//dbone', '', '/'].each do |bad|
      assert_raises(ArgumentError, "#{bad.inspect} should be refused") do
        TransitClient::Sealed.envelope_path(bad)
      end
    end
  end
end

# A certificate comes back one level deeper than a password.
#
# The stored record wraps the value, and for a certificate the value is itself
# JSON. An SDK that returned the record rather than its value would look correct
# on a password and produce an empty certificate here, so this runs the whole
# local chain against a bundle the platform sealed.
class SealedCertificateTest < Minitest::Test
  CERT_FIXTURE = File.expand_path('../../testdata/sealed_certificate.json', __dir__)

  def setup
    @fx = JSON.parse(File.read(CERT_FIXTURE))
    @dek = Base64.decode64(@fx['dek'])
  end

  def test_the_chain_produces_the_bundle_the_platform_sealed
    plaintext = TransitClient::Sealed.open_envelope(
      @fx['envelope'], @dek, @fx['secret_id'], @fx['version']
    )
    value = TransitClient::Sealed.value_from(plaintext)
    assert_equal @fx['expected_value'], value

    cert = TransitClient::Sealed.certificate_from(value)
    assert_includes cert[:certificate], 'BEGIN CERTIFICATE'
    assert_includes cert[:private_key], 'BEGIN PRIVATE KEY'
    assert_includes cert[:ca_chain], 'BEGIN CERTIFICATE'
  end

  def test_a_secret_that_is_not_a_bundle_is_refused
    # An empty certificate returned as success would fail later and somewhere
    # else.
    ['{"value":"a-password"}', 'a-bare-password', '{}',
     '{"certificate":"c"}', '{"private_key":"k"}', '[]'].each do |bad|
      assert_raises(ArgumentError, "#{bad.inspect} should be refused") do
        TransitClient::Sealed.certificate_from(bad)
      end
    end
  end
end

# An envelope written before binding existed carries no AAD, and opens.
#
# Not a rollback -- the thing this must never be confused with. The platform skips
# its own compare for these, so an SDK that insisted on the expected AAD would
# call every pre-binding secret corrupt. All twenty of production's versions were
# unbound when this was measured, so that SDK could not read a single real secret.
class PreBindingEnvelopeTest < Minitest::Test
  LEGACY_FIXTURE = File.expand_path('../../testdata/sealed_legacy_no_aad.json', __dir__)

  def setup
    @fx = JSON.parse(File.read(LEGACY_FIXTURE))
  end

  def test_it_opens_and_is_not_called_corrupt
    plaintext = TransitClient::Sealed.open_envelope(
      @fx['envelope'], Base64.decode64(@fx['dek']), @fx['secret_id'], @fx['version']
    )
    assert_equal @fx['expected_value'], TransitClient::Sealed.value_from(plaintext)
  end

  def test_a_wrong_key_is_still_refused
    # Unbound does not mean unchecked.
    assert_raises(TransitClient::Sealed::CorruptEnvelope) do
      TransitClient::Sealed.open_envelope(
        @fx['envelope'], "\x00" * 32, @fx['secret_id'], @fx['version']
      )
    end
  end
end
