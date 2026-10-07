require 'net/ssh/buffer'
require 'net/ssh/loggable'

module Net
  module SSH
    module Connection
      class HostKeyUpdater
        include Loggable
        include Constants

        HOSTKEYS = "hostkeys-00@openssh.com".freeze
        HOSTKEYS_PROVE = "hostkeys-prove-00@openssh.com".freeze

        def self.mode_for(value)
          case value
          when nil, false, :no, "no", "false" then nil
          when :ask, :append, "ask", "append" then :append
          when true, :yes, :sync, :replace, "yes", "true" then :replace
          else
            raise ArgumentError, "invalid :update_host_keys value: #{value.inspect}"
          end
        end

        def initialize(session, mode = :append)
          self.logger = session.logger
          @session = session
          @mode = mode
          @pending = false

          session.on_global_request(HOSTKEYS) do |data, _want_reply|
            request_update(data)
            :sent
          end
        end

        private

        def request_update(data)
          return unless transport.host_keys_trusted?
          return if @pending

          keys = parse_keys(data)
          return if keys.empty?

          @pending = true
          key_blobs = keys.map(&:to_blob)
          fields = key_blobs.flat_map { |blob| [:string, blob] }

          session.send_global_request(HOSTKEYS_PROVE, *fields) do |success, response|
            @pending = false
            next unless success

            proofs = parse_proofs(response)
            next unless proofs.length == keys.length && proofs.length == key_blobs.length
            next unless proofs.zip(keys).all? { |proof, key| valid_proof?(proof, key, key_blobs) }

            update_host_keys(keys)
          end
        rescue StandardError => e
          @pending = false
          debug { "host key update failed: #{e.class}: #{e.message}" }
        end

        def parse_keys(data)
          keys = []
          loop do
            break if data.eof?
            keys << data.read_key
          end
          keys
        end

        def parse_proofs(packet)
          data = Net::SSH::Buffer.new(packet.content)
          data.read_byte
          proofs = []
          proofs << data.read_string until data.eof?
          proofs
        end

        def valid_proof?(proof_blob, key, key_blobs)
          proof = Net::SSH::Buffer.new(proof_blob)
          signature_type = proof.read_string
          signature = proof.read_string
          return false if proof.available > 0

          signed_data = Net::SSH::Buffer.from(
            :string, HOSTKEYS,
            :string, session_id,
            *key_blobs.flat_map { |blob| [:string, blob] }
          )

          key.ssh_do_verify(signature, signed_data.to_s, host_key: signature_type)
        rescue StandardError
          false
        end

        def update_host_keys(keys)
          transport.host_keys.update_host_keys(keys, replace: @mode == :replace)
        end

        def transport
          session.transport
        end

        def session_id
          transport.algorithms.session_id
        end

        attr_reader :session
      end
    end
  end
end
