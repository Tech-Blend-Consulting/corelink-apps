# frozen_string_literal: true

require 'time'

module TransitClient
  # Leased credentials: request, keep alive while in use, hand back.
  #
  # The other half of what a short-lived credential needs. A secret that rotates
  # is followed by re-reading it; a leased credential expires, and the holder is
  # the only party that knows it is still needed.
  #
  # Renewal bounds itself: CoreLink refuses past the credential's maximum
  # lifetime, so keeping one alive for as long as it is used is not the same as
  # keeping it forever -- which is why #keep_alive is safe to run in the
  # background, and why it stops rather than retrying when it is refused.
  #
  # The wire shapes here were verified against a running CoreLink rather than read
  # off the handler: the listing is wrapped in "data" (not "leases") and the
  # credential is a string (not an object). Both were guessed wrong first.
  #
  # See docs/secret-delivery.md.
  module Leases
    RESOURCE_SECRET = 'secret'
    RESOURCE_DATABASE = 'database'
    RESOURCE_CLOUD = 'cloud'
    RESOURCE_TYPES = [RESOURCE_SECRET, RESOURCE_DATABASE, RESOURCE_CLOUD].freeze

    # This credential will not extend again.
    #
    # It has reached its maximum lifetime, so retrying is pointless: request a new
    # credential. Distinct from an ordinary failure because the recovery differs.
    class LeaseExhausted < StandardError; end

    # The lease is unknown, already revoked, or belongs to another identity --
    # deliberately indistinguishable.
    class LeaseNotFound < StandardError; end

    # A credential and the terms it was issued under.
    class Lease
      attr_reader :id, :credential, :expires_at, :issued_at

      def initialize(id:, credential: '', expires_at: nil, issued_at: nil)
        @id = id
        @credential = credential
        @expires_at = expires_at
        @issued_at = issued_at
      end

      # Seconds left, as last known.
      def remaining
        return 0.0 unless @expires_at

        [Time.parse(@expires_at.to_s) - Time.now, 0.0].max
      rescue ArgumentError, TypeError
        0.0
      end

      # How long the lease was issued for, in seconds. CoreLink reports an expiry
      # on issue and not on renewal, so the original term is what later waits are
      # measured from.
      def term(fallback = 60.0)
        return fallback unless @issued_at && @expires_at

        t = Time.parse(@expires_at.to_s) - Time.parse(@issued_at.to_s)
        t.positive? ? t : fallback
      rescue ArgumentError, TypeError
        fallback
      end

      # Redacts the credential. A lease is logged while tracing its lifecycle far
      # more often than a secret is, so its default rendering must not be where the
      # credential escapes.
      def inspect
        "#<TransitClient::Leases::Lease id=#{@id.inspect} expires_at=#{@expires_at.inspect} credential=<redacted>>"
      end
      alias to_s inspect
    end

    # Build a Lease from either the issue response or a listing row.
    def self.lease_from(payload)
      Lease.new(
        id: payload['lease_id'] || payload['id'] || '',
        credential: payload['credential'] || '',
        expires_at: payload['expires_at'],
        issued_at: payload['issued_at']
      )
    end
  end
end
