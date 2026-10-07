require 'common'
require 'net/ssh/authentication/key_manager'
require 'net/ssh/authentication/methods/publickey'
require 'authentication/methods/common'

module Authentication
  module Methods
    class TestPublickey < NetSSHTest
      include Common

      # A scripted key-exchange used to put a real Algorithms object through
      # an initial key exchange and a rekey, so that tests can verify that
      # the session binding proof is taken from the initial exchange.
      class ScriptedKex
        class << self
          attr_accessor :rounds
        end

        def initialize(*); end

        def exchange_keys
          self.class.rounds.shift
        end
      end

      Net::SSH::Transport::Kex::MAP["scripted-kex-for-session-bind-tests"] = ScriptedKex

      # A fake ssh-agent that speaks just enough of the agent protocol to
      # record the requests it receives and to reply to version negotiation,
      # session binding, identity listing and signing.
      class FakeAgentSocket
        REQUEST_VERSION = 1
        REQUEST_IDENTITIES = 11
        IDENTITIES_ANSWER = 12
        SIGN_REQUEST = 13
        SIGN_RESPONSE = 14
        EXTENSION = 27
        SUCCESS = 6

        attr_reader :requests

        def initialize(identities:, bind_reply: SUCCESS, signature: "fake-signature")
          @identities = identities
          @bind_reply = bind_reply
          @signature = signature
          @requests = []
          @replies = +""
        end

        def send(data, _flags)
          buffer = Net::SSH::Buffer.new(data)
          buffer.read_long # packet length
          type = buffer.read_byte
          @requests << [type, buffer.read]

          case type
          when REQUEST_VERSION
            reply(2) # SSH_AGENT_RSA_IDENTITIES_ANSWER
          when EXTENSION
            reply(@bind_reply)
          when REQUEST_IDENTITIES
            reply(IDENTITIES_ANSWER, :long, @identities.length,
                  *@identities.flat_map { |key| [:string, key.to_blob, :string, "comment"] })
          when SIGN_REQUEST
            reply(SIGN_RESPONSE, :string, Net::SSH::Buffer.from(:string, "ssh-rsa", :string, @signature).to_s)
          else
            raise "unexpected agent request type #{type}"
          end
        end

        def read(length)
          @replies.slice!(0, length)
        end

        def close; end

        private

        def reply(type, *args)
          data = Net::SSH::Buffer.from(*args)
          @replies << [data.length + 1, type, data.to_s].pack("NCA*")
        end
      end

      def test_authenticate_should_return_false_when_no_key_manager_has_been_set
        assert_equal false, subject(key_manager: nil).authenticate("ssh-connection", "jamis")
      end

      def test_authenticate_should_return_false_when_key_manager_has_no_keys
        assert_equal false, subject(keys: []).authenticate("ssh-connection", "jamis")
      end

      def test_authenticate_should_return_false_if_no_keys_can_authenticate
        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert verify_userauth_request_packet(packet, keys.first, false)
          t.return(USERAUTH_FAILURE, :string, "hostbased,password")

          t.expect do |t2, packet2|
            assert_equal USERAUTH_REQUEST, packet2.type
            assert verify_userauth_request_packet(packet2, keys.last, false)
            t2.return(USERAUTH_FAILURE, :string, "hostbased,password")
          end
        end

        assert_equal false, subject.authenticate("ssh-connection", "jamis")
      end

      def test_authenticate_should_raise_if_publickey_disallowed
        key_manager.expects(:sign).with(&signature_parameters(keys.first)).returns("sig-one")

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert verify_userauth_request_packet(packet, keys.first, false)
          t.return(USERAUTH_PK_OK, :string, keys.first.ssh_type, :string, Net::SSH::Buffer.from(:key, keys.first))

          t.expect do |t2, packet2|
            assert_equal USERAUTH_REQUEST, packet2.type
            assert verify_userauth_request_packet(packet2, keys.first, true)
            assert_equal "sig-one", packet2.read_string
            t2.return(USERAUTH_FAILURE, :string, "hostbased,password")
          end
        end

        assert_raises Net::SSH::Authentication::DisallowedMethod do
          subject.authenticate("ssh-connection", "jamis")
        end
      end

      def test_authenticate_should_return_false_if_signature_exchange_fails
        key_manager.expects(:sign).with(&signature_parameters(keys.first)).returns("sig-one")
        key_manager.expects(:sign).with(&signature_parameters(keys.last)).returns("sig-two")

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert verify_userauth_request_packet(packet, keys.first, false)
          t.return(USERAUTH_PK_OK, :string, keys.first.ssh_type, :string, Net::SSH::Buffer.from(:key, keys.first))

          t.expect do |t2, packet2|
            assert_equal USERAUTH_REQUEST, packet2.type
            assert verify_userauth_request_packet(packet2, keys.first, true)
            assert_equal "sig-one", packet2.read_string
            t2.return(USERAUTH_FAILURE, :string, "publickey")

            t2.expect do |t3, packet3|
              assert_equal USERAUTH_REQUEST, packet3.type
              assert verify_userauth_request_packet(packet3, keys.last, false)
              t3.return(USERAUTH_PK_OK, :string, keys.last.ssh_type, :string, Net::SSH::Buffer.from(:key, keys.last))

              t3.expect do |t4, packet4|
                assert_equal USERAUTH_REQUEST, packet4.type
                assert verify_userauth_request_packet(packet4, keys.last, true)
                assert_equal "sig-two", packet4.read_string
                t4.return(USERAUTH_FAILURE, :string, "publickey")
              end
            end
          end
        end

        assert !subject.authenticate("ssh-connection", "jamis")
      end

      def test_authenticate_should_return_true_if_any_key_can_authenticate
        key_manager.expects(:sign).with(&signature_parameters(keys.first)).returns("sig-one")

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert verify_userauth_request_packet(packet, keys.first, false)
          t.return(USERAUTH_PK_OK, :string, keys.first.ssh_type, :string, Net::SSH::Buffer.from(:key, keys.first))

          t.expect do |t2, packet2|
            assert_equal USERAUTH_REQUEST, packet2.type
            assert verify_userauth_request_packet(packet2, keys.first, true)
            assert_equal "sig-one", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis")
      end

      def test_authenticate_rsa_sha2
        key_manager.expects(:sign).with(&signature_parameters_with_alg(keys.first, "rsa-sha2-256")).returns("sig-one")

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert verify_userauth_request_packet(packet, keys.first, false, "rsa-sha2-256")
          t.return(USERAUTH_PK_OK, :string, "rsa-sha2-256", :string, Net::SSH::Buffer.from(:key, keys.first))

          t.expect do |t2, packet2|
            assert_equal USERAUTH_REQUEST, packet2.type
            assert verify_userauth_request_packet(packet2, keys.first, true, "rsa-sha2-256")
            assert_equal "sig-one", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject(pubkey_algorithms: %w[rsa-sha2-256]).authenticate("ssh-connection", "jamis")
      end

      def test_authenticate_rsa_sha2_fallback
        key_manager.expects(:sign).with(&signature_parameters(keys.first)).returns("sig-one")

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert verify_userauth_request_packet(packet, keys.first, false, "rsa-sha2-256")
          t.return(USERAUTH_FAILURE, :string, "publickey")

          t.expect do |t2, packet2|
            assert_equal USERAUTH_REQUEST, packet2.type
            assert verify_userauth_request_packet(packet2, keys.first, false)
            t2.return(USERAUTH_PK_OK, :string, keys.first.ssh_type, :string, Net::SSH::Buffer.from(:key, keys.first))

            t2.expect do |t3, packet3|
              assert_equal USERAUTH_REQUEST, packet3.type
              assert verify_userauth_request_packet(packet3, keys.first, true)
              assert_equal "sig-one", packet3.read_string
              t3.return(USERAUTH_SUCCESS)
            end
          end
        end

        assert subject(pubkey_algorithms: %w[rsa-sha2-256 ssh-rsa]).authenticate("ssh-connection", "jamis")
      end

      def test_authenticate_binds_agent_to_session_with_initial_kex_proof_after_rekey
        hostkey = OpenSSL::PKey::RSA.new(512)
        rekeyed_hostkey = OpenSSL::PKey::RSA.new(512)
        install_rekeyed_algorithms!(
          { session_id: "initial-H", server_key: hostkey, server_sig_blob: "initial-sig" },
          { session_id: "rekeyed-H", server_key: rekeyed_hostkey, server_sig_blob: "rekeyed-sig" }
        )

        fake_agent = FakeAgentSocket.new(identities: [keys.first])
        manager = Net::SSH::Authentication::KeyManager.new(nil, agent_socket_factory: -> { fake_agent })

        expect_publickey_success(keys.first)

        assert subject(key_manager: manager).authenticate("ssh-connection", "jamis")

        # version negotiation, session binding, identity listing, signing:
        # the binding must happen before any signature is requested
        assert_equal [1, 27, 11, 13], fake_agent.requests.map(&:first)

        bind = Net::SSH::Buffer.new(fake_agent.requests[1][1])
        assert_equal "session-bind@openssh.com", bind.read_string
        assert_equal Net::SSH::Buffer.from(:key, hostkey).to_s, bind.read_string
        assert_equal "initial-H", bind.read_string
        assert_equal "initial-sig", bind.read_string
        assert_equal 0, bind.read_byte

        # the data offered for signing is anchored at the initial session id
        sign = Net::SSH::Buffer.new(fake_agent.requests[3][1])
        sign.read_string # key blob
        assert_equal "initial-H", Net::SSH::Buffer.new(sign.read_string).read_string
      end

      def test_authenticate_falls_back_to_unbound_agent_when_bind_is_refused
        install_rekeyed_algorithms!(
          { session_id: "initial-H", server_key: OpenSSL::PKey::RSA.new(512), server_sig_blob: "initial-sig" },
          { session_id: "rekeyed-H", server_key: OpenSSL::PKey::RSA.new(512), server_sig_blob: "rekeyed-sig" }
        )

        fake_agent = FakeAgentSocket.new(identities: [keys.first], bind_reply: 28)
        manager = Net::SSH::Authentication::KeyManager.new(nil, agent_socket_factory: -> { fake_agent })

        expect_publickey_success(keys.first)

        assert subject(key_manager: manager).authenticate("ssh-connection", "jamis")
        assert_equal [1, 27, 11, 13], fake_agent.requests.map(&:first)
        assert_equal :refused, manager.session_bind_status
      end

      def test_authenticate_with_required_session_bind_raises_when_bind_is_refused
        install_rekeyed_algorithms!(
          { session_id: "initial-H", server_key: OpenSSL::PKey::RSA.new(512), server_sig_blob: "initial-sig" },
          { session_id: "rekeyed-H", server_key: OpenSSL::PKey::RSA.new(512), server_sig_blob: "rekeyed-sig" }
        )

        fake_agent = FakeAgentSocket.new(identities: [keys.first], bind_reply: 28)
        manager = Net::SSH::Authentication::KeyManager.new(nil, agent_socket_factory: -> { fake_agent }, session_bind: :required)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert verify_userauth_request_packet(packet, keys.first, false)
          t.return(USERAUTH_PK_OK, :string, keys.first.ssh_type, :string, Net::SSH::Buffer.from(:key, keys.first))
        end

        error = assert_raises(Net::SSH::Authentication::KeyManagerError) do
          subject(key_manager: manager).authenticate("ssh-connection", "jamis")
        end
        assert_match(/refused/, error.message)

        # the agent was bound (and refused) before identities were listed,
        # and no signature was ever requested
        assert_equal [1, 27, 11], fake_agent.requests.map(&:first)
      end

      private

      def expect_publickey_success(key)
        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert verify_userauth_request_packet(packet, key, false)
          t.return(USERAUTH_PK_OK, :string, key.ssh_type, :string, Net::SSH::Buffer.from(:key, key))

          t.expect do |t2, packet2|
            assert_equal USERAUTH_REQUEST, packet2.type
            assert verify_userauth_request_packet(packet2, key, true)
            t2.return(USERAUTH_SUCCESS)
          end
        end
      end

      # Puts a real Algorithms object through an initial key exchange and a
      # rekey (using the given kex results), and installs it on the mock
      # transport, so the session looks like it has been rekeyed.
      def install_rekeyed_algorithms!(*rounds)
        rounds.each do |round|
          round[:shared_secret] ||= OpenSSL::BN.new("1234567890", 10)
          round[:hashing_algorithm] ||= OpenSSL::Digest::SHA1
        end

        algorithms = Net::SSH::Transport::Algorithms.new(transport, {})
        algorithms.instance_variable_set(:@kex, "scripted-kex-for-session-bind-tests")
        algorithms.instance_variable_set(:@encryption_client, "aes256-ctr")
        algorithms.instance_variable_set(:@encryption_server, "aes256-ctr")
        algorithms.instance_variable_set(:@hmac_client, "hmac-sha2-256")
        algorithms.instance_variable_set(:@hmac_server, "hmac-sha2-256")
        algorithms.instance_variable_set(:@compression_client, "none")
        algorithms.instance_variable_set(:@compression_server, "none")

        ScriptedKex.rounds = rounds.dup
        rounds.length.times { algorithms.send(:exchange_keys) }

        transport.instance_variable_set(:@algorithms, algorithms)
        algorithms
      end

      def signature_parameters(key)
        Proc.new do |given_key, data|
          next false unless given_key.to_blob == key.to_blob

          buffer = Net::SSH::Buffer.new(data)
          buffer.read_string == "abcxyz123"      && # session-id
            buffer.read_byte == USERAUTH_REQUEST && # type
            verify_userauth_request_packet(buffer, key, true)
        end
      end

      def signature_parameters_with_alg(key, alg)
        Proc.new do |given_key, data, given_alg|
          next false unless given_key.to_blob == key.to_blob
          next false unless given_alg == alg

          buffer = Net::SSH::Buffer.new(data)
          buffer.read_string == "abcxyz123"      && # session-id
            buffer.read_byte == USERAUTH_REQUEST && # type
            verify_userauth_request_packet(buffer, key, true, alg)
        end
      end

      def verify_userauth_request_packet(packet, key, has_sig, alg = nil)
        packet.read_string == "jamis" && # user-name
          packet.read_string == "ssh-connection" && # next service
          packet.read_string == "publickey"      && # auth-method
          packet.read_bool   == has_sig          && # whether a signature is appended
          packet.read_string == (alg || key.ssh_type) && # ssh key type
          packet.read_buffer.read_key.to_blob == key.to_blob # key
      end

      @@keys = nil
      def keys
        @@keys ||= [OpenSSL::PKey::RSA.new(512), OpenSSL::PKey::DSA.new(1024)]
      end

      def key_manager(options = {})
        @key_manager ||= begin
          manager = stub("key_manager")
          manager.stubs(:each_identity).multiple_yields(*(options[:keys] || keys))
          manager.stubs(:use_agent?).returns(false)
          manager
        end
      end

      def subject(options = {})
        options[:key_manager] = key_manager(options) unless options.key?(:key_manager)
        options[:pubkey_algorithms] = %w[ssh-rsa] unless options.key?(:pubkey_algorithms)
        @subject ||= Net::SSH::Authentication::Methods::Publickey.new(session(options), options)
      end
    end
  end
end
