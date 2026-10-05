# frozen_string_literal: true

require 'base64'
require 'json'

module TransitClient
  # The deployment file: what an application was configured to ask for.
  #
  #   nhiId:          11111111-2222-3333-4444-555555555555
  #   serviceAccount: orders
  #   secrets:
  #     - production/dbone
  #     - production/apikey
  #
  # It tells the SDK which identity to attest as and which secrets to ask for.
  # That is all it is.
  #
  # **Nothing in it grants anything**, and that must stay true even when somebody
  # proposes provisioning grants from it as a convenience. Anyone who can edit a
  # Deployment can add a path to this file; if that provisioned access, "edit
  # deployments" would quietly become "read any secret". The file is a request.
  # The grant on the NHI is the only answer, and CoreLink checks it on every call
  # regardless of what is written here.
  #
  # Neither value is sensitive. The NHI id is a pointer, not a credential:
  # Connect looks the identity up by the id presented and then verifies the
  # evidence against *that identity's* binding, so naming someone else's id and
  # attesting with your own ServiceAccount fails the claim match.
  #
  # **Deliberately not a YAML parser**, even though Ruby ships one. YAML is a
  # large language -- anchors, flow collections, multi-line scalars, implicit
  # typing -- and most of it is ways for a file to mean something other than it
  # appears to. Three keys are needed, so everything else is refused rather than
  # guessed at, and the six SDKs then agree with each other rather than each
  # agreeing with whatever YAML library its language happened to ship.
  #
  # Pinned against the other five SDKs by sdk/testdata/deployment_cases.json.
  module Deployment
    # Where the file is looked for when no path is given.
    DEFAULT_PATH = '/etc/corelink/secrets.yaml'

    # Environment variable that overrides the default path.
    PATH_ENV = 'CORELINK_DEPLOYMENT_FILE'

    SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'

    # A deployment file that could not be read as written.
    class Error < StandardError; end

    # A parsed deployment file.
    class File
      attr_accessor :nhi_id, :service_account, :secrets, :path

      def initialize(nhi_id: '', service_account: '', secrets: nil, path: '')
        @nhi_id = nhi_id
        @service_account = service_account
        @secrets = secrets || []
        @path = path
      end

      # Raise if the pod is not running as the ServiceAccount the file names.
      #
      # **A misconfiguration check, not a security control.** The projected
      # token's claims are read without verifying its signature, because nothing
      # this concludes is trusted: CoreLink verifies that token properly, against
      # the identity's own binding, and that is what decides whether the workload
      # is who it says. Re-deciding it here would be a second authorization path
      # for one question.
      #
      # No name, no token, or an unreadable one: no opinion, no error.
      def verify_service_account
        return if service_account.to_s.empty?

        token = begin
          ::File.read(SA_TOKEN_PATH)
        rescue SystemCallError, IOError
          return
        end

        actual = Deployment.service_account_from_token(token)
        return if actual.nil?
        return if actual == service_account

        raise Error,
              "#{path} names serviceAccount #{service_account.inspect} but this pod is " \
              "running as #{actual.inspect}; the deployment file and the pod spec disagree"
      end
    end

    class << self
      # Read the deployment file, raising if it is missing or unreadable.
      def load(path = nil)
        file = resolve_path(path)
        text = begin
          ::File.read(file)
        rescue SystemCallError, IOError => e
          raise Error, "reading the deployment file #{file}: #{e.message}"
        end

        d = begin
          parse(text)
        rescue Error => e
          raise Error, "#{file}: #{e.message}"
        end
        d.path = file

        raise Error, "#{file}: nhiId is required; it names the identity to attest as" if d.nhi_id.empty?

        if d.secrets.empty?
          raise Error,
                "#{file}: secrets is required; an application asks for what it was " \
                'configured to ask for rather than discovering what exists'
        end

        d
      end

      # #load, except that a missing file returns nil.
      #
      # A file that exists and does not parse is still an error: the difference
      # that matters is "no file" against "a file I could not read", and silently
      # ignoring the second would run the application on a configuration nobody
      # wrote.
      def load_if_present(path = nil)
        file = resolve_path(path)
        return nil unless ::File.exist?(file)

        load(file)
      end

      # Read the one shape this file has, and refuse the rest.
      def parse(text)
        d = File.new
        seen = {}
        list_key = nil

        text.split("\n").each_with_index do |raw, idx|
          n = idx + 1

          raise Error, "line #{n}: tabs are not allowed in indentation" if raw.include?("\t")

          # A comment is only a comment at the start of a line here. Stripping a
          # trailing "#" would corrupt any value that legitimately contains one.
          trimmed = raw.strip
          next if trimmed.empty? || trimmed.start_with?('#')

          if trimmed.start_with?('---') || trimmed.start_with?('...')
            raise Error, "line #{n}: multiple documents are not supported"
          end
          if trimmed.include?('&') || trimmed.include?('*')
            raise Error, "line #{n}: anchors and aliases are not supported"
          end

          # A list entry, which belongs to the key above it.
          if trimmed.start_with?('- ') || trimmed == '-'
            raise Error, "line #{n}: a list entry with no key above it" if list_key.nil?

            item = scalar(trimmed[1..].strip, n)
            raise Error, "line #{n}: an empty list entry" if item.empty?
            raise Error, "line #{n}: #{list_key.inspect} does not take a list" if list_key != 'secrets'

            d.secrets << item
            next
          end

          # Anything else must be a key at the left margin. Leading whitespace is
          # what makes it indented; trailing whitespace is invisible and harmless.
          if raw.sub(/\A +/, '') != raw
            raise Error, "line #{n}: unexpected indentation; this file is a flat set of keys"
          end
          raise Error, "line #{n}: expected \"key: value\"" unless trimmed.include?(':')

          key, value = trimmed.split(':', 2)
          # YAML needs a space after the colon to make this a mapping at all --
          # "nhiId:abc" is a plain scalar, not a key.
          if !value.empty? && !value.start_with?(' ')
            raise Error, "line #{n}: a key needs a space after its colon"
          end

          key = key.strip
          value = value.strip

          # Two values for one key: a reader has to pick, and either choice is
          # somebody's surprise.
          raise Error, "line #{n}: #{key.inspect} appears more than once" if seen[key]

          seen[key] = true
          list_key = nil

          case key
          when 'nhiId', 'nhiID', 'nhi_id'
            d.nhi_id = scalar(value, n)
          when 'serviceAccount', 'service_account'
            d.service_account = scalar(value, n)
          when 'secrets'
            if value.empty?
              # The list form; entries follow on their own lines.
              list_key = 'secrets'
              next
            end
            d.secrets << scalar(value, n)
          else
            # Refused rather than ignored. A typo in a key an application relies
            # on would otherwise be silence, and the application would run asking
            # for nothing.
            raise Error, "line #{n}: unknown key #{key.inspect}"
          end
        end

        d
      end

      # The ServiceAccount name from a projected token, or nil. The signature is
      # not checked; see File#verify_service_account.
      def service_account_from_token(token)
        parts = token.to_s.strip.split('.')
        return nil unless parts.length == 3

        payload = parts[1]
        payload += '=' * ((4 - (payload.length % 4)) % 4)
        claims = begin
          JSON.parse(Base64.urlsafe_decode64(payload))
        rescue ArgumentError, JSON::ParserError
          return nil
        end
        return nil unless claims.is_a?(Hash)

        # The subject, which is the canonical and flat form:
        #   system:serviceaccount:<namespace>:<name>
        # Every projected token carries it, so there is no need to reach into
        # the nested kubernetes.io claim for the same name.
        bits = claims['sub'].to_s.split(':')
        return bits[3] if bits.length == 4 && bits[0] == 'system'

        nil
      end

      private

      def resolve_path(path)
        return path unless path.to_s.empty?

        env = ENV.fetch(PATH_ENV, '')
        env.empty? ? DEFAULT_PATH : env
      end

      # Read one plain value, refusing the YAML forms this does not implement.
      def scalar(v, n)
        return '' if v.empty?

        if v.start_with?('[') || v.start_with?('{')
          raise Error, "line #{n}: flow collections are not supported; use a \"- item\" list"
        end
        if v.start_with?('|') || v.start_with?('>')
          raise Error, "line #{n}: multi-line scalars are not supported"
        end

        if v.length >= 2
          first = v[0]
          last = v[-1]
          if (first == '"' && last == '"') || (first == "'" && last == "'")
            inner = v[1..-2]
            if inner.include?(first)
              raise Error, "line #{n}: escapes inside a quoted value are not supported"
            end

            return inner
          end
          raise Error, "line #{n}: a quoted value is not closed" if ['"', "'"].include?(first)
        elsif ['"', "'"].include?(v)
          raise Error, "line #{n}: a quoted value is not closed"
        end

        # YAML refuses ": " inside a plain scalar because it cannot tell the
        # value from a nested mapping.
        if v.include?(': ') || v.end_with?(':')
          raise Error, "line #{n}: a value containing a colon must be quoted"
        end
        # Ambiguous: YAML would read " #" as a trailing comment, and a reader
        # that guesses either way is wrong for somebody.
        raise Error, "line #{n}: a value containing # must be quoted" if v.include?('#')

        v
      end
    end
  end
end
