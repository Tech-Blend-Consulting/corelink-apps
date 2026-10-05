# frozen_string_literal: true

require_relative 'transit_client/deployment'
require_relative 'transit_client/leases'
require_relative 'transit_client/client'
require_relative 'transit_client/fingerprint'
require_relative 'transit_client/watcher'

# Transit API client for Tech Blend Secrets Management.
module TransitClient
  VERSION = '0.1.0'

  # Convenience wrapper mirroring the other SDKs' compute_fingerprint helper.
  def self.compute_fingerprint(nhi_id)
    Fingerprint.compute(nhi_id)
  end
end
