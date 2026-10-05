# frozen_string_literal: true

require 'digest'
require 'socket'
require 'rbconfig'
require 'open3'

module TransitClient
  # Runtime fingerprint computation for NHI identity verification.
  #
  # Same construction as the Python and Go SDKs: the digest is
  # sha256(binary_hash_bytes || machine_id || hostname || nhi_id).
  #
  # The binary hash covers the running interpreter, so the value differs per
  # language runtime on the same host. That is intended: each workload enrols
  # its own NHI, and the fingerprint binds a session to that running artifact.
  module Fingerprint
    module_function

    # Compute a runtime fingerprint for this process.
    #
    # @param nhi_id [String]
    # @return [Array(String, Hash)] hex digest and metadata
    def compute(nhi_id)
      meta = {}

      # Binary hash: SHA-256 of the running interpreter, matching the Python
      # SDK's use of sys.executable.
      binary_hash =
        begin
          Digest::SHA256.hexdigest(File.binread(RbConfig.ruby))
        rescue StandardError
          Digest::SHA256.hexdigest(RUBY_DESCRIPTION)
        end
      meta['binary_hash'] = binary_hash

      machine_id = read_machine_id
      meta['machine_id'] = machine_id

      hostname = Socket.gethostname
      meta['hostname'] = hostname
      meta['os'] = host_os
      meta['arch'] = RbConfig::CONFIG['host_cpu']

      digest = Digest::SHA256.new
      digest << [binary_hash].pack('H*')
      digest << machine_id
      digest << hostname
      digest << nhi_id.to_s

      [digest.hexdigest, meta]
    end

    # Read the platform-specific machine ID, falling back to the hostname.
    def read_machine_id
      case host_os
      when 'linux'
        id = safe_read('/etc/machine-id')
        return id if id && !id.empty?

        # Container fallback: the cgroup path ends in the container ID.
        cgroup = safe_read('/proc/self/cgroup')
        if cgroup
          cgroup.each_line do |line|
            last = line.strip.split('/').last
            return last[0, 12] if last && last.length >= 12
          end
        end
      when 'darwin'
        out = safe_exec('ioreg', '-rd1', '-c', 'IOPlatformExpertDevice')
        out&.each_line do |line|
          next unless line.include?('IOPlatformUUID')

          return line.split('=', 2)[1].to_s.strip.delete('"')
        end
      when 'windows'
        out = safe_exec('reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid')
        out&.each_line do |line|
          return line.split.last if line.include?('MachineGuid')
        end
      end

      Socket.gethostname
    end

    def host_os
      case RbConfig::CONFIG['host_os']
      when /darwin/i then 'darwin'
      when /mswin|mingw|cygwin/i then 'windows'
      when /linux/i then 'linux'
      else RbConfig::CONFIG['host_os'].downcase
      end
    end

    def safe_read(path)
      File.read(path).strip
    rescue StandardError
      nil
    end

    def safe_exec(*cmd)
      out, _err, status = Open3.capture3(*cmd)
      status.success? ? out : nil
    rescue StandardError
      nil
    end
  end
end
