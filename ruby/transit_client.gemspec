# frozen_string_literal: true

require_relative 'lib/transit_client'

Gem::Specification.new do |spec|
  spec.name        = 'techblend-transit'
  spec.version     = TransitClient::VERSION
  spec.summary     = 'Transit API client for Tech Blend Secrets Management'
  spec.description = 'NHI-attested client for the Tech Blend CoreLink transit API.'
  spec.homepage    = 'https://github.com/techblend/secrets-mgmt'
  spec.authors     = ['Tech Blend']
  spec.license     = 'Nonstandard'

  # 3.1 because opening a sealed envelope needs an openssl that can set
  # additional authenticated data. The openssl gem shipped with macOS system
  # Ruby 2.6 (2.1.2, against LibreSSL) cannot: auth_data= raises whatever order
  # it is called in, and auth_tag_len= segfaults. There is no fallback, since a
  # secret cannot be opened without its AAD.
  spec.required_ruby_version = '>= 3.1'
  spec.files = Dir['lib/**/*.rb'] + ['README.md']
  spec.require_paths = ['lib']

  # Standard library only -- no runtime dependencies in the credential path.
  # AES-GCM comes from openssl, which must be backed by OpenSSL rather than
  # LibreSSL; see required_ruby_version above.
end
