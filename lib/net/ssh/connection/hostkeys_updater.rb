require 'net/ssh/buffer'
require 'net/ssh/known_hosts'
require 'net/ssh/loggable'

module Net
  module SSH
    module Connection
      # Implements the client side of OpenSSH's host key update protocol
      # extension (see the PROTOCOL document in the OpenSSH source tree).
      #
      # After a session has been authenticated, a server may advertise all of
      # its host keys with a hostkeys-00@openssh.com global request. When the
      # :update_host_keys option is enabled and the session's current host key
      # was already known (i.e. the session is trusted), the client asks the
      # server to prove possession of the advertised private keys with a
      # hostkeys-prove-00@openssh.com request, and only then records the new
      # keys in the user's known hosts files.
      #
      # Two modes are supported:
      #
      # * :append (or true) -- newly advertised keys are appended to the
      #   known hosts files once proven.
      # * :sync -- like :append, but keys recorded for the host that the
      #   server no longer advertises are removed as well. Removal only
      #   happens when every advertised key was proven; if any proof fails
      #   the known hosts files are left untouched.
      class HostKeysUpdater
        include Loggable

        # The global request a server sends to advertise its host keys.
        REQUEST = 'hostkeys-00@openssh.com'

        # The global request a client sends to ask the server to prove
        # possession of the private halves of its advertised host keys.
        PROVE_REQUEST = 'hostkeys-prove-00@openssh.com'

        # The connection session this updater works on behalf of.
        attr_reader :session

        def initialize(session)
          @session = session
          self.logger = session.logger
        end

        # Handles a hostkeys-00@openssh.com global request. +data+ is the
        # request payload: a sequence of strings, each a public key blob.
        # Returns true when the advertisement was accepted for processing,
        # false when it was ignored.
        def handle(data)
          return false unless mode && trusted_session?

          advertised = parse_keys(data)
          return false if advertised.empty?

          unknown = advertised.reject { |_blob, key| known_key?(key) }

          if unknown.empty?
            update_known_hosts([], advertised)
          else
            request_proof(unknown, advertised)
          end

          true
        end

        private

        # The configured update mode: :append, :sync, or nil when the
        # extension is disabled.
        def mode
          case session.options[:update_host_keys]
          when :sync, 'sync' then :sync
          when nil, false, :never, 'no' then nil
          else :append
          end
        end

        # Only sessions whose current host key was found in the known hosts
        # files (before this session verified it) may update host keys; a
        # key that was merely accepted on first use proves nothing about the
        # server.
        def trusted_session?
          trusted = session.transport.host_key_trusted
          debug { "ignoring #{REQUEST}: session host key is not trusted" } unless trusted
          trusted
        end

        def known_hosts_class
          session.transport.options.fetch(:known_hosts, KnownHosts)
        end

        def host_string
          session.transport.host_keys.host
        end

        def session_id
          session.transport.algorithms.session_id
        end

        # Parses the advertised key blobs, returning a list of
        # [blob, key] pairs. Blobs that cannot be parsed or whose type is
        # not supported for known hosts files are skipped.
        def parse_keys(data)
          keys = []
          buffer = data.is_a?(Net::SSH::Buffer) ? data : Net::SSH::Buffer.new(data)
          until buffer.available.zero?
            blob = buffer.read_string
            key = parse_key(blob)
            keys << [blob, key] if key
          end
          keys
        end

        def parse_key(blob)
          key = Net::SSH::Buffer.new(blob).read_key
          key if key && KnownHosts::SUPPORTED_TYPE.include?(key.ssh_type)
        rescue StandardError, NotImplementedError
          nil
        end

        def known_key?(key)
          session.transport.host_keys.any? do |known|
            if known.respond_to?(:matches_key?)
              known.matches_key?(key)
            else
              known.ssh_type == key.ssh_type && known.to_blob == key.to_blob
            end
          end
        end

        # Sends a hostkeys-prove-00@openssh.com request for the unknown keys
        # and applies the update once the server's reply has been verified.
        def request_proof(unknown, advertised)
          extra = unknown.flat_map { |blob, _key| [:string, blob] }
          session.send_global_request(PROVE_REQUEST, *extra) do |success, packet|
            if success && verify_proofs(unknown, packet)
              update_known_hosts(unknown.map { |_blob, key| key }, advertised)
            else
              debug { "#{PROVE_REQUEST} failed; known hosts files left unchanged" }
            end
          end
        end

        # Verifies the signatures returned by the server. Each signature
        # covers, in SSH string encoding: the literal request name, the
        # session identifier, and the public key blob. Returns true only if
        # every advertised unknown key was proven.
        def verify_proofs(unknown, packet)
          signatures = []
          signatures << packet.read_string until packet.available.zero?
          return false unless signatures.size == unknown.size

          unknown.zip(signatures).all? do |(blob, key), signature|
            verify_proof(blob, key, signature)
          end
        rescue StandardError => e
          debug { "malformed #{PROVE_REQUEST} reply: #{e.message}" }
          false
        end

        def verify_proof(blob, key, signature)
          sig_buffer = Net::SSH::Buffer.new(signature)
          sig_type = sig_buffer.read_string
          sig = sig_buffer.read_string
          return false unless sig_buffer.available.zero?
          return false unless signature_type_match?(key, sig_type)

          data = Net::SSH::Buffer.from(:string, PROVE_REQUEST, :string, session_id, :string, blob).to_s
          key.ssh_do_verify(sig, data, host_key: sig_type)
        rescue StandardError => e
          debug { "could not verify #{PROVE_REQUEST} signature: #{e.message}" }
          false
        end

        def signature_type_match?(key, sig_type)
          if key.ssh_type == 'ssh-rsa'
            %w[ssh-rsa rsa-sha2-256 rsa-sha2-512].include?(sig_type)
          else
            key.ssh_type == sig_type
          end
        end

        # Applies the update to the user's known hosts files: appends the
        # newly proven keys and, in :sync mode, removes the recorded keys
        # the server no longer advertises.
        def update_known_hosts(new_keys, advertised)
          remove_keys = retired_keys(advertised) if mode == :sync
          known_hosts_class.update(host_string, new_keys, remove_keys || [], session.options)
          session.transport.reset_host_keys!
          info { "updated known hosts for #{host_string}: #{new_keys.size} added, #{(remove_keys || []).size} removed" }
        end

        # The plain host keys currently recorded for the host that the
        # server no longer advertises. Certificate authority entries are
        # never removed.
        def retired_keys(advertised)
          advertised_keys = advertised.map { |_blob, key| key }
          session.transport.host_keys.select do |known|
            !known.is_a?(Net::SSH::HostKeyEntries::CertAuthority) &&
              advertised_keys.none? { |key| same_key?(key, known) }
          end
        end

        def same_key?(key, other)
          key.ssh_type == other.ssh_type && key.to_blob == other.to_blob
        end
      end
    end
  end
end
