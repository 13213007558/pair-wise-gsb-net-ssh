require_relative '../common'
require 'net/ssh/transport/algorithms'

module Transport
  class TestStrictKex < NetSSHTest
    include Net::SSH::Transport::Constants

    KEX_ALGORITHM = 'strict-kex-test'
    KEX_COOKIE = "\x01" * 16

    def setup
      Net::SSH::Transport::Kex::MAP[KEX_ALGORITHM] = ScriptedKex
    end

    def teardown
      Net::SSH::Transport::Kex::MAP.delete(KEX_ALGORITHM)
    end

    def test_strict_handshake_resets_each_direction_at_newkeys_boundary
      connection = strict_connection

      connection.feed_plaintext(server_kexinit)
      connection.kex_packets << kex_reply
      connection.outer_packets << server_newkeys
      connection.poll_message(:nonblock)

      assert connection.algorithms.strict_kex
      assert_equal [0], connection.client_hmacs.first.sequences

      service_request = Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, 'ssh-userauth')
      connection.send_message(service_request)
      connection.feed_authenticated(Net::SSH::Buffer.from(:byte, SERVICE_ACCEPT, :string, 'ssh-userauth'), sequence: 0)
      accepted = connection.poll_message(:nonblock)
      assert_equal SERVICE_ACCEPT, accepted.type
      assert_equal [0, 1], connection.client_hmacs.first.sequences
      assert_equal [0, 3], connection.server_hmacs.first.sequences
    end

    def test_strict_handshake_rejects_ignore_before_kexinit
      connection = strict_connection

      connection.feed_plaintext(ignore_packet)
      connection.feed_plaintext(server_kexinit)

      assert_raises(Net::SSH::Exception) { connection.poll_message(:block) }
    end

    def test_strict_handshake_rejects_ignore_between_kexinit_and_newkeys
      connection = strict_connection

      connection.feed_plaintext(ignore_packet)
      connection.feed_plaintext(server_kexinit)
      connection.kex_packets << kex_reply
      connection.outer_packets << server_newkeys

      assert_raises(Net::SSH::Exception) { connection.poll_message(:block) }
    end

    def test_strict_handshake_allows_send_and_receive_newkeys_to_cross
      connection = strict_connection

      connection.feed_plaintext(server_kexinit)
      connection.kex_packets << kex_reply
      connection.outer_packets << server_newkeys

      packet = connection.poll_message(:nonblock)
      assert_nil packet
      assert connection.algorithms.initialized?
      assert_equal [0], connection.client_hmacs.first.sequences
    end

    def test_rekey_keeps_strict_mode_and_resets_sequences_again
      connection = strict_connection
      accept_initial_kex(connection)

      connection.send_message(Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, 'ssh-userauth'))
      connection.feed_authenticated(Net::SSH::Buffer.from(:byte, SERVICE_ACCEPT, :string, 'ssh-userauth'), sequence: 0)
      connection.poll_message(:block)

      connection.algorithms.rekey!
      connection.feed_authenticated(server_kexinit, sequence: 2)
      connection.kex_packets << [kex_reply, 3]
      connection.outer_packets << { packet: server_newkeys, sequence: 4 }
      connection.poll_message(:nonblock)
      connection.poll_message(:nonblock)

      connection.send_message(Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, 'ssh-userauth'))
      connection.feed_authenticated(Net::SSH::Buffer.from(:byte, SERVICE_ACCEPT, :string, 'ssh-userauth'), sequence: 0)
      accepted = connection.poll_message(:block)
      assert_equal SERVICE_ACCEPT, accepted.type

      assert connection.algorithms.strict_kex
      assert_equal [[0, 1, 2, 3], [0, 1]], connection.client_hmacs.map(&:sequences)
      assert_equal [[0, 3, 2, 4, 3, 5, 4, 6], [0, 7]], connection.server_hmacs.map(&:sequences)
    end

    def test_initial_handshake_without_strict_extension_keeps_legacy_sequences
      connection = strict_connection
      connection.algorithms
      connection.feed_plaintext(server_kexinit(strict: false))
      connection.kex_packets << kex_reply
      connection.outer_packets << server_newkeys

      3.times { connection.poll_message(:block) }

      assert !connection.algorithms.strict_kex

      connection.send_message(Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, 'ssh-userauth'))
      connection.feed_authenticated(Net::SSH::Buffer.from(:byte, SERVICE_ACCEPT, :string, 'ssh-userauth'), sequence: 3)
      connection.poll_message(:block)

      assert_equal [3], connection.client_hmacs.first.sequences
      assert_equal [3, 3], connection.server_hmacs.first.sequences
    end

    private

    def strict_connection
      connection = StrictConnection.new
      connection.algorithms[:kex].unshift(KEX_ALGORITHM)
      connection.algorithms[:encryption_client].unshift('none')
      connection.algorithms[:encryption_server].unshift('none')
      connection.algorithms.start
      connection
    end

    def accept_initial_kex(connection)
      connection.feed_plaintext(server_kexinit)
      connection.kex_packets << kex_reply
      connection.outer_packets << server_newkeys
      connection.poll_message(:nonblock)
    end

    def ignore_packet
      Net::SSH::Buffer.from(:byte, IGNORE, :string, 'strict?')
    end

    def kex_reply
      Net::SSH::Buffer.from(:byte, KEXECDH_REPLY,
                            :string, 'host key',
                            :string, 'server ephemeral key',
                            :string, 'signature')
    end

    def server_newkeys
      Net::SSH::Buffer.from(:byte, NEWKEYS)
    end

    def server_kexinit(strict: true)
      kex = [KEX_ALGORITHM].tap do |algorithms|
        algorithms << Net::SSH::Transport::Algorithms::STRICT_KEX_SERVER if strict
      end.join(',')

      Net::SSH::Buffer.from(:byte, KEXINIT,
                            :raw, KEX_COOKIE,
                            :string, kex,
                            :string, 'ssh-rsa',
                            :string, 'none',
                            :string, 'none',
                            :string, 'hmac-sha2-256',
                            :string, 'hmac-sha2-256',
                            :string, 'none',
                            :string, 'none',
                            :string, '',
                            :string, '',
                            :bool, false,
                            :long, 0)
    end

    class SequenceHMAC
      attr_reader :sequences

      def self.key_length
        0
      end

      def self.mac_length
        4
      end

      def self.aead
        false
      end

      def self.etm
        false
      end

      def initialize(*)
        @sequences = []
      end

      def digest(data)
        @sequences << data.unpack1('N')
        'macs'
      end

      def mac_length
        4
      end

      def aead
        false
      end

      def etm
        false
      end
    end

    class ScriptedKex < Net::SSH::Transport::Kex::Abstract
      def digester
        OpenSSL::Digest::SHA256
      end

      def exchange_keys(&block)
        result = {
          session_id: 'session id',
          hashing_algorithm: digester,
          shared_secret: OpenSSL::BN.new('42', 10)
        }
        connection.send_message(Net::SSH::Buffer.from(:byte, KEXECDH_INIT))
        expect_message(KEXECDH_REPLY)
        confirm_newkeys(result) do |direction|
          block.call(direction, result) if block
        end
        result
      end

      private
      def generate_key
        nil
      end
    end

    class StrictConnection
      include Net::SSH::Loggable
      include Net::SSH::Transport::Constants

      attr_reader :algorithms, :socket, :server_version, :options
      attr_reader :client_hmacs, :server_hmacs, :kex_packets, :outer_packets

      def initialize
        @kex_packets = []
        @outer_packets = []
        @options = {}
        @server_version = OpenStruct.new(version: 'SSH-2.0-test')
        @socket = PacketSocket.new
        @client_hmacs = []
        @server_hmacs = []
        @expect_newkeys = false
        @algorithms = Net::SSH::Transport::Algorithms.new(self, @options)
      end

      def host_keys
        []
      end

      def host_key_verifier
        @host_key_verifier ||= Object.new.tap do |verifier|
          def verifier.verify(**_); true; end
          def verifier.verify_signature; yield; end
        end
      end

      def send_message(message)
        socket.enqueue_packet(message)
      end

      def next_message
        @expect_newkeys = true
        item = @kex_packets.shift
        if item.is_a?(Array)
          feed_authenticated(item.first, sequence: item.last)
        elsif item
          feed_plaintext(item)
        end
        packet = poll_message(:nonblock)
        return packet if packet

        item = @outer_packets.shift
        if item.is_a?(Hash)
          feed_authenticated(item[:packet], sequence: item[:sequence])
        elsif item
          feed_plaintext(item)
        end
        packet = poll_message(:nonblock)
        packet ||= poll_message(:nonblock)
        @expect_newkeys = false
        packet || raise(Net::SSH::Exception, 'expected packet in strict kex test')
      end

      def pending_newkeys?
        !@outer_packets.empty?
      end

      def poll_message(mode = :nonblock, _consume_queue = true)
        loop do
          packet = socket.next_packet(mode)
          return nil if packet.nil?

          error = algorithms.strict_kex_packet_error(packet)
          raise Net::SSH::Exception, error if error

          case packet.type
          when IGNORE
            error = algorithms.strict_kex_packet_error(packet)
            raise Net::SSH::Exception, error if error
            next
          when KEXINIT
            algorithms.accept_kexinit(packet)
          when NEWKEYS
            return packet if !algorithms.initialized?
            return packet if @expect_newkeys && pending_newkeys?

            next
          else
            return packet
          end
        end
      end

      def feed_plaintext(packet)
        socket.feed(framed_packet(packet, hmac: nil))
      end

      def feed_authenticated(packet, sequence:)
        frame = packet.to_s
        padding = 8 - ((frame.bytesize + 5) % 8)
        padding += 8 if padding < 4
        packet_length = frame.bytesize + padding + 1
        message = [packet_length, padding, frame, 'x' * padding].pack('NCA*A*')
        mac = socket.server.hmac.digest([sequence, message].pack('NA*'))
        socket.feed(message + mac)
      end

      def configure_client(options = {}, reset_sequence: false)
        hmac = SequenceHMAC.new
        @client_hmacs << hmac
        options[:hmac] = hmac
        socket.client.set(options, reset_sequence: reset_sequence)
      end

      def configure_server(options = {}, reset_sequence: false)
        hmac = SequenceHMAC.new
        options[:hmac] = hmac
        @server_hmacs << hmac
        socket.server.set(options, reset_sequence: reset_sequence)
      end

      def hint(*); end

      private

      def framed_packet(packet, hmac:, sequence: nil)
        frame = packet.to_s
        padding = 8 - ((frame.bytesize + 5) % 8)
        padding += 8 if padding < 4
        packet_length = frame.bytesize + padding + 1
        message = [packet_length, padding, frame, 'x' * padding].pack('NCA*A*')
        return message if hmac.nil?

        message + hmac.digest([sequence, message].pack('NA*'))
      end
    end

    class PacketSocket
      include Net::SSH::Transport::PacketStream

      attr_writer :logger

      def initialize
        initialize_ssh
      end

      def feed(frame)
        if @packet
          @input = Net::SSH::Buffer.new(@packet.content[0, 4] + @input.to_s)
        end
        @input.append(frame)
      end

      def next_packet(_mode = :nonblock, _timeout = nil)
        packet = poll_next_packet
        @input.consume! if packet
        packet
      end

      private
    end
  end
end
