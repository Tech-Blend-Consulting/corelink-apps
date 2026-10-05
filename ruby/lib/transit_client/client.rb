# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'
require 'uri'
require 'monitor'
require_relative 'fingerprint'
# The sealed path lives in Sealed and this file is its only caller, so without
# this require get_secret_sealed raises NameError for any application that loads
# the library the ordinary way. It went unnoticed because the sealed tests
# require the module directly, so they proved the crypto and never the wiring.
require_relative 'sealed'

module TransitClient
  # Raised for any non-success response or transport failure.
  class Error < StandardError; end

  # Client for the Tech Blend Transit API.
  #
  # Authentication is NHI (Non-Human Identity) passwordless attestation. Call
  # #bootstrap before any other call; the client then renews its session in a
  # background thread every 50 minutes.
  class Client
    K8S_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'
    HEARTBEAT_SECONDS = 50 * 60
    APPROVAL_POLL_SECONDS = 5
    APPROVAL_ATTEMPTS = 60 # five minutes

    # @param transit_url  [String] base URL of the transit agent
    # @param platform_url [String] base URL of the platform (NHI connect/heartbeat)
    # @param nhi_id       [String] NHI identity for attestation
    # @param ca_cert_file [String] path to a CA bundle for TLS pinning
    def initialize(transit_url:, platform_url: '', nhi_id: '', ca_cert_file: '', attest: nil)
      raise ArgumentError, 'transit_url is required' if transit_url.to_s.empty?

      @url = transit_url.sub(%r{/+\z}, '')
      @platform_url = platform_url.to_s.sub(%r{/+\z}, '')
      @nhi_id = nhi_id.to_s
      # attest supplies the attestation to present, instead of the SDK detecting
      # one: anything responding to #call and returning [type, evidence].
      #
      # For a workload that runs nowhere the SDK can recognise -- a product with
      # no connector, no pod and no instance identity document -- and federates
      # to its own OIDC issuer instead. Return ['oidc', token].
      #
      # Callable rather than a string, because these tokens are short lived by
      # design: it is called on every connect and reconnect, so a session that
      # drops at three in the morning re-mints rather than replaying something
      # that expired hours ago.
      #
      # Nothing it returns authorises anything: CoreLink verifies the token
      # against the issuer pinned to this identity, and the grant decides what
      # the identity may do.
      @attest = attest
      @ca_cert_file = ca_cert_file.to_s
      @session_id = nil
      @heartbeat_thread = nil
      @closed = false
      @monitor = Monitor.new
    end

    # Connect via NHI attestation and start the background heartbeat.
    def bootstrap
      nhi_connect
      start_heartbeat
      nil
    end

    # The secrets available to this client.
    #
    # A connector serves envelopes by name and offers no way to enumerate them:
    # an application asks for what it was configured to ask for. There is nothing
    # to list, so this raises rather than returning an empty array that would
    # read as "no secrets".
    def list_secrets
      raise 'a connector serves envelopes by name and offers no listing; ' \
            'name the secrets this application needs'
    end

    # The value of a single secret by name.
    #
    # Takes the sealed envelope from the connector, asks CoreLink for the key to
    # that secret, and opens it here. The connector cannot read what it served
    # and CoreLink never sees the plaintext, so the value exists in this process
    # and nowhere else.
    #
    # It used to ask the connector for plaintext. That endpoint answers 410 now,
    # and this goes the sealed way instead, so an application already calling
    # get_secret needs no change.
    #
    # @return [String]
    def get_secret(name)
      get_secret_sealed(name)
    end

    # Open a secret from a sealed envelope. See #get_secret.
    #
    # Requires secrets:unwrap on the secret, and a connector granted
    # secrets:cache on it.
    #
    # A stale envelope is retried once with the connector told to refetch, which
    # is the case this exists for: the connector holding a version CoreLink has
    # since rotated past. A second failure of the same kind is reported as stale
    # rather than retried forever.
    #
    # @return [String]
    def get_secret_sealed(name)
      raise 'get_secret_sealed needs a connector; set transit_url' if @url.to_s.empty?
      if @platform_url.to_s.empty? || @nhi_id.to_s.empty?
        raise 'get_secret_sealed needs an identity; set platform_url and nhi_id'
      end

      begin
        open_sealed(name, false)
      rescue Sealed::StaleEnvelope
        open_sealed(name, true)
      end
    end

    # @return [Array<Hash>] entries with 'name', 'file_name' and 'content'
    def list_configs
      authed_get("#{@url}/v1/configs").fetch('configs', [])
    end

    # @return [String]
    def get_config(name)
      authed_get("#{@url}/v1/configs/#{encode(name)}").fetch('content', '')
    end

    # Stop the heartbeat and release the NHI session. Safe to call twice.
    def close
      @closed = true
      thread = @monitor.synchronize { @heartbeat_thread }
      thread&.kill
      @monitor.synchronize { @heartbeat_thread = nil }
      nhi_disconnect
      nil
    end

    # A TLS bundle, fetched through the sealed path and parsed here.
    #
    # A certificate is a secret whose value is a bundle, so it needs no delivery
    # mechanism of its own: the same envelope, the same key, the same binding.
    # The connector used to serve a bundle's parts from plaintext it held in
    # memory, which was the last readable thing in that process.
    #
    # The private key exists in this process and nowhere else.
    #
    # @return [Hash] with :certificate, :private_key and :ca_chain
    def get_certificate(name)
      Sealed.certificate_from(get_secret_sealed(name))
    end

    # Ask CoreLink for a credential leased for a while.
    #
    # +resource_type+ is one of Leases::RESOURCE_SECRET, RESOURCE_DATABASE or
    # RESOURCE_CLOUD. A zero TTL takes CoreLink's default; asking for longer than
    # policy allows is CoreLink's decision, and the lease says what was granted.
    def request_credential(resource_type, resource_id, ttl_seconds = 0)
      if @platform_url.to_s.empty? || @nhi_id.to_s.empty?
        raise Error, 'request_credential needs an identity; set platform_url and nhi_id'
      end
      unless Leases::RESOURCE_TYPES.include?(resource_type)
        raise ArgumentError, "resource type #{resource_type.inspect} is not one of #{Leases::RESOURCE_TYPES.join(', ')}"
      end
      raise ArgumentError, 'a resource id is required' if resource_id.to_s.empty?

      body = { 'resource_type' => resource_type, 'resource_id' => resource_id }
      body['ttl_seconds'] = ttl_seconds.to_i if ttl_seconds.to_i.positive?

      res = platform_request(:post, '/api/v1/nhi-agent/credentials', body: body)
      raise Error, "CoreLink refused to issue a credential (status #{res.code})" unless res.code.to_i == 200

      lease = Leases.lease_from(parse_json(res))
      raise Error, 'CoreLink issued a credential with no lease id' if lease.id.to_s.empty?

      lease
    end

    # Extend a lease, or say why it will not extend.
    #
    # Raises Leases::LeaseExhausted at the credential's maximum lifetime. That is
    # not a failure to retry: request a new credential.
    def renew_lease(lease_id)
      raise ArgumentError, 'a lease id is required' if lease_id.to_s.empty?

      res = platform_request(:post, "/api/v1/nhi-agent/leases/#{encode(lease_id)}/renew")
      case res.code.to_i
      when 200 then nil
      when 422 then raise Leases::LeaseExhausted, 'this credential cannot be extended further'
      when 404 then raise Leases::LeaseNotFound, 'lease not found'
      else raise Error, "renewing the lease failed (status #{res.code})"
      end
    end

    # Hand a credential back before it expires.
    #
    # Worth doing rather than letting it lapse: it stops working at once. A lease
    # already gone is not an error, because the caller's intent is satisfied.
    def release_credential(lease_id)
      raise ArgumentError, 'a lease id is required' if lease_id.to_s.empty?

      res = platform_request(:delete, "/api/v1/nhi-agent/credentials/#{encode(lease_id)}")
      return if [200, 204, 404].include?(res.code.to_i)

      raise Error, "releasing the credential failed (status #{res.code})"
    end

    # The identity's active leases, without their credentials.
    #
    # The material is handed over once, at issue.
    def list_leases
      res = platform_request(:get, '/api/v1/nhi-agent/credentials')
      raise Error, "listing leases failed (status #{res.code})" unless res.code.to_i == 200

      # "data" is the key CoreLink sends.
      (parse_json(res)['data'] || []).map { |row| Leases.lease_from(row) }
    end

    # Renew a lease in the background for as long as it is in use.
    #
    # Renews at half the remaining life and stops when CoreLink refuses, calling
    # +on_expiry+ once with the reason -- which is how an application learns it
    # must request a new credential. Returns a lambda that stops the renewals; it
    # does not release the lease.
    def keep_alive(lease, on_expiry = nil)
      stop = false
      mutex = Mutex.new
      floor = @keep_alive_floor || 1.0
      term = lease.term

      thread = Thread.new do
        remaining = lease.remaining
        remaining = term if remaining <= 0
        loop do
          wait = [remaining / 2, floor].max
          sleep wait
          break if mutex.synchronize { stop }

          begin
            renew_lease(lease.id)
          rescue StandardError => e
            on_expiry&.call(e)
            break
          end
          remaining = term
        end
      end
      thread.abort_on_exception = false

      lambda do
        mutex.synchronize { stop = true }
        thread.kill
        nil
      end
    end

    private

    # Send an authenticated request to CoreLink.
    def platform_request(method, path, body: nil)
      sid = @monitor.synchronize { @session_id }
      raise Error, 'no CoreLink session; call bootstrap first' if sid.to_s.empty?

      http_request(method, "#{@platform_url}#{path}", body: body,
                                                      headers: { 'X-NHI-Session' => sid })
    end

    # Detect the runtime and return attestation evidence.
    #
    # Kubernetes first (the kubelet projects a service account token), then a
    # host fingerprint. The evidence MUST NOT be logged -- under Kubernetes it
    # is a service account JWT.
    #
    # @return [Array(String, String)] type and evidence
    def collect_attestation
      # The caller first: a workload federating to its own issuer knows how to
      # get its token and the SDK does not; a pod or a host is the other way
      # round.
      return @attest.call if @attest

      detect_attestation
    end

    # @return [Array(String, String)] type and evidence
    def detect_attestation
      begin
        token = File.read(K8S_TOKEN_PATH).strip
        return ['kubernetes', token] unless token.empty?
      rescue StandardError
        # not running under Kubernetes
      end

      fingerprint, = Fingerprint.compute(@nhi_id)
      ['host', fingerprint]
    end

    def nhi_connect
      type, evidence = collect_attestation
      res = http_request(
        :post,
        "#{@platform_url}/api/v1/nhi-agent/connect",
        body: { nhi_id: @nhi_id, attestation: { type: type, evidence: evidence } }
      )

      raise Error, 'NHI identity verification failed' if res.code.to_i == 403
      ensure_ok!(res, 'NHI connect')

      data = parse_json(res)
      session_id = data['session_id']
      raise Error, 'NHI connect returned no session_id' if session_id.nil? || session_id.empty?

      # A missing status means "active" -- older platforms omit the field.
      status = data['status'].to_s.empty? ? 'active' : data['status']
      case status
      when 'pending_approval' then poll_approval(session_id)
      when 'active' then nil
      else raise Error, "NHI connect returned unexpected status: #{status}"
      end

      @monitor.synchronize { @session_id = session_id }
    end

    # Poll until an admin approves or rejects, or five minutes elapse.
    def poll_approval(session_id)
      url = "#{@platform_url}/api/v1/nhi-agent/connect/#{session_id}/status"
      APPROVAL_ATTEMPTS.times do
        sleep APPROVAL_POLL_SECONDS
        begin
          res = http_request(:get, url)
          next unless res.code.to_i < 300

          status = parse_json(res)['status']
          return if status == 'active'
          raise Error, 'Connect request rejected by admin' if status == 'rejected'
        rescue Error
          raise
        rescue StandardError
          next # transient; keep polling
        end
      end
      raise Error, 'Approval timeout (5 minutes)'
    end

    def start_heartbeat
      @monitor.synchronize do
        @heartbeat_thread = Thread.new do
          until @closed
            sleep HEARTBEAT_SECONDS
            break if @closed

            nhi_heartbeat
          end
        end
        @heartbeat_thread.abort_on_exception = false
      end
    end

    def nhi_heartbeat
      type, evidence = collect_attestation
      res = http_request(
        :post,
        "#{@platform_url}/api/v1/nhi-agent/heartbeat",
        body: { attestation: { type: type, evidence: evidence } },
        headers: auth_header
      )
      # The platform rejects a heartbeat whose evidence no longer matches the
      # session -- expected after a host change, so reconnect rather than die.
      nhi_connect if [401, 403].include?(res.code.to_i)
    rescue StandardError
      begin
        nhi_connect
      rescue StandardError
        # leave the session as-is; the next heartbeat retries
      end
    end

    def nhi_disconnect
      sid = @monitor.synchronize { @session_id }
      return if sid.nil?

      begin
        http_request(:post, "#{@platform_url}/api/v1/nhi-agent/disconnect",
                     headers: { 'X-NHI-Session' => sid }, read_timeout: 5)
      rescue StandardError
        # best effort -- the session expires on its own
      end
      @monitor.synchronize { @session_id = nil }
    end

    def auth_header
      sid = @monitor.synchronize { @session_id }
      sid ? { 'X-NHI-Session' => sid } : {}
    end

    # GET with session auth; on 401 reconnect and retry exactly once.
    # One attempt at fetching, unwrapping and opening.
    def open_sealed(name, refresh)
      envelope = fetch_envelope(name, refresh)
      dek, version, authoritative_name = unwrap_dek(envelope['secret_id'])

      # The name CoreLink says this id belongs to must be the name that was
      # asked for. See Sealed::WrongSecret: the AAD binds an envelope to its own
      # id and version, so a substituted secret opens cleanly and only this
      # comparison catches it.
      asked = name.to_s.gsub(%r{\A/+|/+\z}, '')
      if !authoritative_name.to_s.empty? && authoritative_name != asked
        raise Sealed::WrongSecret,
              "asked for #{asked} and the connector answered with #{authoritative_name}"
      end

      # The key belongs to whatever version CoreLink currently holds. A
      # different one means this envelope is behind, and saying so is clearer
      # than letting the AEAD fail for an unexplained reason.
      unless version == envelope['version']
        raise Sealed::StaleEnvelope,
              "the connector served version #{envelope['version']}, CoreLink is on #{version}"
      end

      plaintext = Sealed.open_envelope(envelope['envelope'], dek, envelope['secret_id'], version)
      Sealed.value_from(plaintext)
    end

    # Take the sealed envelope from the connector.
    #
    # Unauthenticated, because the connector has nothing to decide: what it
    # serves cannot be opened without a grant CoreLink checks.
    def fetch_envelope(name, refresh)
      url = "#{@url}/v1/envelopes/#{Sealed.envelope_path(name)}"
      url += '?refresh=1' if refresh
      res = http_request(:get, url)
      unless res.code.to_i == 200
        raise Error, "the connector has no envelope for #{name.inspect} (status #{res.code})"
      end

      envelope = parse_json(res)
      if envelope['envelope'].to_s.empty? || envelope['secret_id'].to_s.empty?
        raise Error, "the connector served an incomplete envelope for #{name.inspect}"
      end

      envelope
    end

    # Ask CoreLink for the key to one secret.
    #
    # CoreLink unwraps its own copy, so nothing this process holds takes part: an
    # application handed somebody else's ciphertext cannot have it opened by
    # naming a secret it is entitled to.
    def unwrap_dek(secret_id)
      sid = @monitor.synchronize { @session_id }
      raise Error, 'no CoreLink session; call bootstrap first' if sid.to_s.empty?

      res = http_request(
        :post,
        "#{@platform_url}/api/v1/nhi-agent/secrets/#{encode(secret_id)}/unwrap",
        headers: { 'X-NHI-Session' => sid }
      )
      raise Error, "CoreLink refused to unwrap (status #{res.code})" unless res.code.to_i == 200

      body = parse_json(res)
      dek = Base64.decode64(body['dek'].to_s)
      raise Error, 'CoreLink returned no key' if dek.empty?

      # The name is CoreLink's answer to "which secret is this id?", which only
      # it can give. The caller compares it against what it asked for.
      [dek, body['version'], body['name'].to_s]
    end

    def authed_get(url)
      res = http_request(:get, url, headers: auth_header)
      if res.code.to_i == 401
        begin
          nhi_connect
          res = http_request(:get, url, headers: auth_header)
        rescue StandardError
          # fall through and report the original failure
        end
      end
      ensure_ok!(res, "GET #{URI(url).path}")
      parse_json(res)
    end

    def http_request(method, url, body: nil, headers: {}, read_timeout: 10)
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      # Pinning replaces the default trust store rather than adding to it: a
      # pinned deployment should not accept a public CA.
      http.ca_file = @ca_cert_file if http.use_ssl? && !@ca_cert_file.empty?
      http.open_timeout = read_timeout
      http.read_timeout = read_timeout

      # :delete is here for releasing a lease. Anything unrecognised falls back to
      # GET rather than guessing, which is the safe direction: a read that fails
      # is better than a write nobody asked for.
      request_class = case method
                      when :post then Net::HTTP::Post
                      when :delete then Net::HTTP::Delete
                      else Net::HTTP::Get
                      end
      req = request_class.new(uri.request_uri)
      req['Accept'] = 'application/json'
      headers.each { |k, v| req[k] = v }
      if body
        req['Content-Type'] = 'application/json'
        req.body = JSON.generate(body)
      end

      http.request(req)
    rescue StandardError => e
      raise Error, "request failed: #{e.class}"
    end

    def parse_json(res)
      return {} if res.body.nil? || res.body.empty?

      JSON.parse(res.body)
    rescue JSON::ParserError
      {}
    end

    # Raise with status and a short body excerpt -- never the request payload,
    # which carries attestation evidence.
    def ensure_ok!(res, what)
      code = res.code.to_i
      return if code >= 200 && code < 300

      excerpt = res.body.to_s[0, 200]
      raise Error, "#{what} failed: HTTP #{code}#{excerpt.empty? ? '' : " -- #{excerpt}"}"
    end

    def encode(name)
      URI.encode_www_form_component(name.to_s)
    end
  end
end
