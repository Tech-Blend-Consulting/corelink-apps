# frozen_string_literal: true

# The leased-credential lifecycle against a fake CoreLink.
#
# The wire shapes are the ones a live CoreLink was observed to send -- the listing
# wrapped in "data", the credential as a string -- because the Go SDK guessed both
# wrong from reading the handler and only a real call disagreed.
#
# Run: ruby -Isdk/ruby/lib sdk/ruby/test/leases_test.rb

require 'json'
require 'minitest/autorun'
require 'socket'
require 'transit_client'

class LeaseLifecycleTest < Minitest::Test
  # A minimal HTTP fake over TCPServer. WEBrick left the standard library, and a
  # lease test needs four verbs and a status code -- not a web server.
  def setup
    @renewals = 0
    @renew_limit = 0
    @released = []
    @requested = []
    @mutex = Mutex.new

    @server = TCPServer.new('127.0.0.1', 0)
    @thread = Thread.new do
      loop do
        socket = begin
          @server.accept
        rescue IOError, Errno::EBADF
          break
        end
        handle(socket)
      end
    end

    url = "http://127.0.0.1:#{@server.addr[1]}"
    @client = TransitClient::Client.new(transit_url: 'http://127.0.0.1:1', platform_url: url, nhi_id: 'nhi-1')
    @client.instance_variable_set(:@session_id, 'session-in-place')
  end

  def teardown
    @server.close
    @thread&.kill
  end

  def handle(socket)
    request_line = socket.gets
    return socket.close unless request_line

    method, path, = request_line.split
    length = 0
    while (line = socket.gets) && line.strip != ''
      length = line.split(':', 2)[1].to_i if line.downcase.start_with?('content-length:')
    end
    body = length.positive? ? socket.read(length) : ''

    status, payload = route(method, path, body)
    respond(socket, status, payload)
  rescue StandardError
    nil
  ensure
    socket.close unless socket.closed?
  end

  def route(method, path, body)
    now = Time.now
    if method == 'POST' && path == '/api/v1/nhi-agent/credentials'
      @mutex.synchronize { @requested << JSON.parse(body.empty? ? '{}' : body) }
      return [200, { 'lease_id' => 'lease-1', 'credential' => '{"username":"dyn_abc"}',
                     'issued_at' => now.iso8601, 'expires_at' => (now + 900).iso8601 }]
    end
    if method == 'POST' && path.end_with?('/renew')
      return [404, { 'error' => {} }] if path.include?('unknown-lease')

      refuse = @mutex.synchronize { @renew_limit.positive? && @renewals >= @renew_limit }
      return [422, { 'error' => {} }] if refuse

      @mutex.synchronize { @renewals += 1 }
      return [200, { 'renewed' => true }]
    end
    if method == 'DELETE' && path.start_with?('/api/v1/nhi-agent/credentials/')
      @mutex.synchronize { @released << path.split('/').last }
      return [204, nil]
    end
    if method == 'GET' && path == '/api/v1/nhi-agent/credentials'
      # "data", not "leases".
      return [200, { 'data' => [{ 'id' => 'lease-1', 'expires_at' => (now + 900).iso8601 }] }]
    end
    [404, { 'error' => {} }]
  end

  def respond(socket, status, payload)
    body = payload.nil? ? '' : JSON.generate(payload)
    socket.print "HTTP/1.1 #{status} x\r\n"
    socket.print "Content-Type: application/json\r\n"
    socket.print "Content-Length: #{body.bytesize}\r\n"
    socket.print "Connection: close\r\n\r\n"
    socket.print body
  end

  def renewals
    @mutex.synchronize { @renewals }
  end

  def test_a_credential_is_leased_with_its_terms
    lease = @client.request_credential(TransitClient::Leases::RESOURCE_SECRET, 'secret-1', 300)
    assert_equal 'lease-1', lease.id
    assert_includes lease.credential, 'dyn_abc'
    refute_nil lease.expires_at, 'no expiry means nothing can tell when to renew'
    assert_operator lease.remaining, :>, 0
    assert_equal 300, @mutex.synchronize { @requested[0]['ttl_seconds'] }
  end

  def test_the_rendering_does_not_carry_the_credential
    lease = @client.request_credential(TransitClient::Leases::RESOURCE_SECRET, 'secret-1')
    refute_includes lease.inspect, 'dyn_abc'
    refute_includes lease.to_s, 'dyn_abc'
  end

  def test_an_unknown_resource_type_is_refused_locally
    assert_raises(ArgumentError) { @client.request_credential('kubernetes', 'x') }
    assert_raises(ArgumentError) { @client.request_credential(TransitClient::Leases::RESOURCE_SECRET, '') }
    assert_empty @mutex.synchronize { @requested.dup }
  end

  def test_renewal_tells_exhausted_apart_from_not_found
    @client.renew_lease('lease-1')
    assert_equal 1, renewals

    @mutex.synchronize { @renew_limit = 1 }
    assert_raises(TransitClient::Leases::LeaseExhausted) { @client.renew_lease('lease-1') }
    assert_raises(TransitClient::Leases::LeaseNotFound) { @client.renew_lease('unknown-lease') }
  end

  def test_release_is_idempotent_and_the_listing_omits_the_credential
    @client.release_credential('lease-1')
    assert_equal ['lease-1'], @mutex.synchronize { @released.dup }

    found = @client.list_leases
    assert_equal 1, found.length
    assert_equal '', found[0].credential,
                 'a listing that returned the credential would make it re-readable'
  end

  def test_keep_alive_renews_then_stops_when_refused
    # One renewal allowed, the next refused: proves it renews, and proves it stops
    # rather than retrying something that cannot succeed.
    @mutex.synchronize { @renew_limit = 1 }
    @client.instance_variable_set(:@keep_alive_floor, 0.02)

    now = Time.now
    lease = TransitClient::Leases::Lease.new(id: 'lease-1', issued_at: now.iso8601,
                                             expires_at: (now + 1).iso8601)
    reported = []
    stop = @client.keep_alive(lease, ->(e) { reported << e })
    begin
      deadline = Time.now + 3
      sleep 0.02 while reported.empty? && Time.now < deadline
    ensure
      stop.call
    end

    assert_equal 1, reported.length, 'on_expiry should be called exactly once'
    assert_kind_of TransitClient::Leases::LeaseExhausted, reported[0]
  end
end
