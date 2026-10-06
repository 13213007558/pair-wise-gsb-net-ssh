# encoding: ASCII-8BIT

require_relative '../common'
require 'delegate'
require 'net/ssh/transport/session'
require 'net/ssh/transport/hmac'
require 'net/ssh/transport/kex'

module Transport
  # End-to-end style tests for the OpenSSH strict KEX extension
  # ("Terrapin", CVE-2023-48795). They drive a real PacketStream over a
  # socket pair and assert on the packet sequence numbers that actually
  # reach the MAC/cipher layer, not merely on a boolean flag.
  class TestStrictKex < NetSSHTest
    include Net::SSH::Transport::Constants

    STRICT_CLIENT = Net::SSH::Transport::Algorithms::STRICT_KEX_CLIENT
    STRICT_SERVER = Net::SSH::Transport::Algorithms::STRICT_KEX_SERVER
    TEST_KEX = 'strict-kex-test'

    # Minimal key exchange: pretends a full exchange happened and drives
    # the NEWKEYS boundary (which is what strict KEX cares about).
    class FakeKex < Net::SSH::Transport::Kex::Abstract
      def initialize(algorithms, connection, _data)
        @algorithms = algorithms
        @connection = connection
      end

      def digester
        OpenSSL::Digest::SHA1
      end

      def exchange_keys
        confirm_newkeys
        {
          session_id: 'strict-kex-session',
          server_key: OpenSSL::PKey::RSA.new(512),
          shared_secret: OpenSSL::BN.new('1234567890', 10),
          hashing_algorithm: digester
        }
      end

      private

      def verify_server_key(_key); end

      def verify_signature(_result)
        'strict-kex-session'
      end
    end

    Net::SSH::Transport::Kex::MAP[TEST_KEX] = FakeKex

    # Persistent, per-direction wrapper around the HMAC. It records every
    # sequence number handed to #digest (the sequence number is encoded as
    # the first four bytes of the MAC input) and survives algorithm
    # reconfiguration (#swap), so a direction's full sequence stream across a
    # NEWKEYS boundary can be observed even though the real HMAC object is
    # replaced.
    class RecordingHMAC < SimpleDelegator
      attr_reader :sequences, :role

      def initialize(hmac, role)
        super(hmac)
        @role = role
        @sequences = []
      end

      def swap(hmac)
        __setobj__(hmac)
      end

      def digest(data)
        @sequences << data[0, 4].unpack1('N')
        __getobj__.digest(data)
      end
    end

    def setup
      @recordings = []
      @recorders = {}
      Net::SSH::Transport::Algorithms::ALGORITHMS[:kex] << TEST_KEX
    end

    def teardown
      Net::SSH::Transport::Algorithms::ALGORITHMS[:kex].delete(TEST_KEX)
    end

    def test_strict_handshake_enters_strict_mode_and_resets_sequences_at_newkeys
      with_recording_hmac do
        session, server_io = start_session(server_kex: [STRICT_SERVER, TEST_KEX])

        assert session.algorithms.strict_kex?

        # The client MACs KEXINIT as packet 0 and NEWKEYS already as packet 0
        # again after its own NEWKEYS boundary reset.
        assert_equal [0, 0], client_sequences

        # The receive direction has processed the server's KEXINIT (0) and
        # NEWKEYS (1) under the initial exchange HMAC.
        assert_equal [0, 1], server_sequences

        # After the handshake each direction proceeds on its own fresh counter.
        # NEWKEYS itself was MAC'd with the post-KEX HMAC at sequence 0; the
        # SERVICE_REQUEST is the next encrypted packet at sequence 1. On the
        # receive side the counter was independently reset by the server's
        # NEWKEYS, so the IGNORE arrives as sequence 0.
        write_server_frame(server_io, ignore_packet)
        session.poll_message
        session.send_message(Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, 'ssh-userauth'))

        assert_equal [0, 0, 1], client_sequences
        # NEWKEYS reset the receive counter, so the IGNORE arrives at 0 again.
        assert_equal [0, 1, 0], server_sequences
      end
    end

    def test_sequences_remain_continuous_for_legacy_server_without_extension
      with_recording_hmac do
        session, server_io = start_session(server_kex: [TEST_KEX])

        assert !session.algorithms.strict_kex?

        write_server_frame(server_io, ignore_packet)
        session.poll_message
        session.send_message(Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, 'ssh-userauth'))

        # Without strict mode the client still switches to a fresh post-KEX
        # HMAC object but its counter is not reset to zero: the first
        # encrypted packet continues at sequence 2.
        assert_equal [0, 1, 2], client_sequences
        assert_equal [0, 1, 2], server_sequences
      end
    end

    def test_ignore_packet_before_initial_kexinit_is_detected
      assert_raises(Net::SSH::ProtocolError) do
        start_session(server_kex: [STRICT_SERVER, TEST_KEX],
                      pre_kexinit: [ignore_packet])
      end
    end

    def test_ignore_packet_interleaved_into_strict_exchange_is_rejected
      assert_raises(Net::SSH::ProtocolError) do
        start_session(server_kex: [STRICT_SERVER, TEST_KEX],
                      pre_newkeys: [ignore_packet])
      end
    end

    def test_ignore_packet_interleaved_into_legacy_exchange_is_ignored
      session, server_io = start_session(server_kex: [TEST_KEX],
                                         pre_newkeys: [ignore_packet])
      assert !session.algorithms.strict_kex?
      assert session.algorithms.initialized?
      server_io.close
    end

    def test_rekey_keeps_strict_mode_and_resets_both_directions
      with_recording_hmac do
        session, server_io = start_session(server_kex: [STRICT_SERVER, TEST_KEX])

        write_kexinit(server_io, [STRICT_SERVER, TEST_KEX])
        write_newkeys(server_io)
        session.rekey!

        assert session.algorithms.strict_kex?

        # Initial exchange: KEXINIT 0, NEWKEYS 0 (reset before sending). The
        # rekey KEXINIT is itself encrypted (sequence 1), then NEWKEYS is
        # MAC'd with 0 after the send direction resets again.
        assert_equal [0, 0, 1, 0], client_sequences
        # Receive side: initial KEXINIT 0, initial NEWKEYS 1 then reset; the
        # rekey KEXINIT is the first packet after that reset (0), and the
        # second NEWKEYS is MAC'd with 1 before the direction resets again.
        assert_equal [0, 1, 0, 1], server_sequences
      end
    end

    def test_rekey_without_extension_after_strict_negotiation_is_rejected
      session, server_io = start_session(server_kex: [STRICT_SERVER, TEST_KEX])

      write_kexinit(server_io, [TEST_KEX])
      assert_raises(Net::SSH::ProtocolError) { session.rekey! }
      server_io.close
    end

    def test_client_kexinit_always_advertises_strict_extension
      begin
        session, server_io, captured = start_session(server_kex: [TEST_KEX])
        assert session.algorithms.kex.include?(TEST_KEX)
        assert captured.string.dup.force_encoding(Encoding::BINARY).include?(STRICT_CLIENT)
      ensure
        server_io&.close
      end
    end

    private

    def session_options
      {
        kex: ["+#{TEST_KEX}"],
        host_key: 'ssh-rsa',
        encryption: 'none',
        hmac: 'none',
        compression: 'none',
        append_all_supported_algorithms: false
      }
    end

    def stub_server_version
      version = "SSH-2.0-Ruby/Net::SSH::Test\r\n"
      stub('server_version', version: version)
    end

    def start_session(server_kex:, pre_kexinit: [], pre_newkeys: [])
      client_io, server_io = Socket.pair(:UNIX, :STREAM, 0)
      captured = StringIO.new
      client_io.singleton_class.send(:define_method, :send) do |data, flags = 0|
        captured.write(data)
        super(data, flags)
      end

      pre_kexinit.each { |payload| write_frame(server_io, payload) }
      write_kexinit(server_io, server_kex)
      pre_newkeys.each { |payload| write_frame(server_io, payload) }
      write_newkeys(server_io)

      Net::SSH::Transport::ServerVersion.stubs(:new).returns(stub_server_version)
      Socket.stubs(:tcp).returns(client_io)
      session = Net::SSH::Transport::Session.new('net.ssh.test', session_options)
      [session, server_io, captured]
    end

    def write_kexinit(io, kex_algorithms)
      payload = Net::SSH::Buffer.from(
        :byte, KEXINIT,
        :long, 1, :long, 2, :long, 3, :long, 4,
        :mstring, [kex_algorithms.join(','), 'ssh-rsa', 'none', 'none', 'none', 'none'],
        :mstring, ['none', 'none', '', ''],
        :bool, false, :long, 0
      )
      write_frame(io, payload)
    end

    def write_newkeys(io)
      write_frame(io, Net::SSH::Buffer.from(:byte, NEWKEYS))
    end

    def ignore_packet
      Net::SSH::Buffer.from(:byte, IGNORE, :string, 'pwned')
    end

    def write_server_frame(io, payload)
      write_frame(io, payload)
    end

    # Frames a binary payload as an unencrypted SSH packet whose length is
    # aligned to the identity cipher block size (8 bytes).
    def write_frame(io, payload)
      payload = payload.to_s
      packet_length = payload.bytesize + 1
      padding_length = 8 - ((4 + packet_length) % 8)
      padding_length += 8 if padding_length < 4
      packet_length += padding_length
      padding = Array.new(padding_length) { rand(256) }.pack('C*')
      io.write([packet_length].pack('N') + [padding_length].pack('C') + payload + padding)
    end

    def with_recording_hmac
      recordings = @recordings
      recorders = @recorders
      Net::SSH::Transport::State.class_eval do
        alias_method :__strict_kex_original_initialize, :initialize
        define_method(:initialize) do |socket, role|
          __strict_kex_original_initialize(socket, role)
          @hmac = recorders[role] ||= RecordingHMAC.new(@hmac, role)
          recordings << @hmac unless recordings.include?(@hmac)
        end
        alias_method :__strict_kex_original_set, :set
        define_method(:set) do |values|
          __strict_kex_original_set(values)
          if @hmac.is_a?(RecordingHMAC)
            @hmac.swap(values[:hmac])
          else
            @hmac = recorders[@role] || RecordingHMAC.new(@hmac, @role)
          end
        end
      end
      yield
    ensure
      Net::SSH::Transport::State.class_eval do
        remove_method :initialize
        alias_method :initialize, :__strict_kex_original_initialize
        remove_method :__strict_kex_original_initialize
        remove_method :set
        alias_method :set, :__strict_kex_original_set
        remove_method :__strict_kex_original_set
      end
    end

    def client_sequences
      @recordings.select { |recorder| recorder.role == :client }.map(&:sequences).flatten
    end

    def server_sequences
      @recordings.select { |recorder| recorder.role == :server }.map(&:sequences).flatten
    end
  end
end
