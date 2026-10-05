# frozen_string_literal: true

# A connector that answers with a different secret than the one asked for.
#
# The attack the AAD does not cover. An envelope is bound to its own id and
# version, so a substituted secret is internally consistent: the key CoreLink
# returns for that id opens it, the version matches, the tag verifies. Every
# cryptographic check passes and the application gets a value it did not ask for.
#
# The fixture is a real one, produced by the platform's own crypto, served under
# the wrong name. Nothing is forged -- that is the point. The only thing that can
# catch it is comparing the name CoreLink says the id belongs to against the name
# the application asked for.
#
# Needs Ruby >= 3.1: macOS system Ruby links LibreSSL, where setting an AEAD auth
# tag segfaults.
#
# Run: ruby -Isdk/ruby/lib sdk/ruby/test/substitution_test.rb

require 'json'
require 'minitest/autorun'
require 'socket'
require 'transit_client'

class SubstitutedSecretTest < Minitest::Test
  FIXTURE = File.expand_path('../../testdata/sealed_envelope.json', __dir__)

  # The name the fixture's secret really has, and the name the application asks
  # for. The connector answers the second with the first.
  REAL_NAME = 'production/other-secret'
  ASKED_NAME = 'production/dbone'

  def setup
    @fx = JSON.parse(File.read(FIXTURE))
    # What the unwrap endpoint reports as the authoritative name; each test sets
    # it before calling.
    @authoritative_name = REAL_NAME
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
    # One server standing in for both the connector and CoreLink.
    @client = TransitClient::Client.new(transit_url: url, platform_url: url, nhi_id: 'nhi-1')
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
    while (line = socket.gets) && line.strip != ''
      # headers discarded; nothing here authorises anything
    end

    status, payload = route(method, path)
    respond(socket, status, payload)
  rescue StandardError
    nil
  ensure
    socket.close unless socket.closed?
  end

  def route(method, path)
    # The connector: asked for one name, answers with the other secret's id and
    # envelope. A real envelope, just not the requested one.
    if method == 'GET' && path.start_with?('/v1/envelopes/')
      return [200, { 'secret_id' => @fx['secret_id'], 'name' => ASKED_NAME,
                     'version' => @fx['version'], 'envelope' => @fx['envelope'] }]
    end

    # CoreLink: unwraps its own copy and says which name the id belongs to.
    if method == 'POST' && path.end_with?('/unwrap')
      name = @mutex.synchronize { @authoritative_name }
      return [200, { 'dek' => @fx['dek'], 'version' => @fx['version'], 'name' => name }]
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

  def test_a_substituted_secret_is_refused
    err = assert_raises(TransitClient::Sealed::WrongSecret) do
      @client.get_secret_sealed(ASKED_NAME)
    end
    # The message has to name both, or an operator cannot tell which connector
    # lied about what.
    assert_includes err.message, ASKED_NAME
    assert_includes err.message, REAL_NAME
  end

  def test_the_right_secret_still_opens
    # The same path with the names agreeing: proves the check refuses
    # substitution rather than refusing everything.
    @mutex.synchronize { @authoritative_name = ASKED_NAME }
    assert_equal @fx['expected_value'], @client.get_secret_sealed(ASKED_NAME)
  end

  def test_no_name_from_the_platform_does_not_refuse
    # An older CoreLink that does not send the name yet. Refusing here would
    # break every application against it; the AAD still binds id and version.
    @mutex.synchronize { @authoritative_name = '' }
    assert_equal @fx['expected_value'], @client.get_secret_sealed(ASKED_NAME)
  end
end
