require_relative '../common'
require 'socket'
require 'net/ssh/authentication/key_manager'
require 'net/ssh/transport/algorithms'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/transport/hmac'

module Authentication
  class TestAgentSessionBinding < NetSSHTest
    def setup
      super
      @recorded = []
      @agent_buffer = String.new(encoding: Encoding::BINARY)
    end

    def test_binds_before_identities_and_signing_using_initial_kex_after_rekey
      binding = session_binding_after_rekey
      user_key = OpenSSL::PKey::RSA.new(512).public_key
      client, server = UNIXSocket.pair
      agent_thread = Thread.new { run_fake_agent(server, user_key) }
      Thread.pass

      manager = Net::SSH::Authentication::KeyManager.new(nil,
                                                          agent_socket_factory: -> { client },
                                                          agent_session_binding: binding)

      identities = []
      manager.each_identity { |identity| identities << identity }
      raise @agent_error if @agent_error
      identity = identities.first
      signature = manager.sign(identity, "authentication data")
      manager.finish
      agent_thread.join(1)
      agent_thread.kill
      raise @agent_error if @agent_error

      assert_equal "fake signature", signature
      assert_equal user_key.to_blob, identities.first.to_blob
      assert_equal [1, 27, 11, 13], @recorded.map(&:first)

      body = Net::SSH::Buffer.new(@recorded[1][1])
      assert_equal Net::SSH::Authentication::Agent::SESSION_BIND_EXTENSION, body.read_string
      assert_equal binding[:host_key].to_blob, body.read_string
      assert_equal "initial session id", body.read_string
      assert_equal "initial host signature blob", body.read_string
      assert_equal false, body.read_bool
    end

    def test_unsupported_binding_can_fall_back_to_unbound_agent
      manager = bind_manager(5)
      assert manager.bind_agent!
    end

    def test_unsupported_binding_is_rejected_when_unbound_agent_is_disallowed
      manager = bind_manager(5, allow_unbound_agent: false)
      assert_raises(Net::SSH::Authentication::AgentExtensionUnsupported) { manager.bind_agent! }
    end

    def test_explicit_extension_failure_is_not_treated_as_unsupported
      manager = bind_manager(28)
      assert_raises(Net::SSH::Authentication::AgentExtensionFailed) { manager.bind_agent! }
    end

    private

    def bind_manager(extension_response, options = {})
      user_key = OpenSSL::PKey::RSA.new(512).public_key
      client, server = UNIXSocket.pair
      Thread.new { run_simple_agent(server, user_key, extension_response) }
      Net::SSH::Authentication::KeyManager.new(nil, {
        agent_socket_factory: -> { client },
        agent_session_binding: {
          host_key: user_key,
          session_id: "session",
          host_signature: "signature"
        }
      }.merge(options))
    end

    def run_simple_agent(socket, user_key, extension_response)
      loop do
        packet = read_packet(socket)
        break unless packet

        case packet[:type]
        when 1 then send_agent_packet(socket, 5)
        when 27 then send_agent_packet(socket, extension_response)
        when 11
          send_agent_packet(socket, 12,
                            :long, 1,
                            :string, user_key.to_blob,
                            :string, "key")
        end
      end
    rescue EOFError, Errno::ENOTCONN, IOError
    ensure
      socket.close unless socket.closed?
    end

    def session_binding_after_rekey
      transport = MockTransport.new(user_known_hosts_file: '/dev/null',
                                    global_known_hosts_file: '/dev/null')
      transport.expect {}
      algorithms = Net::SSH::Transport::Algorithms.new(transport, {})

      algorithms.instance_variable_set(:@kex, 'diffie-hellman-group14-sha256')
      algorithms.instance_variable_set(:@host_key, 'ssh-rsa')
      algorithms.instance_variable_set(:@encryption_client, 'aes256-ctr')
      algorithms.instance_variable_set(:@encryption_server, 'aes256-ctr')
      algorithms.instance_variable_set(:@hmac_client, 'hmac-sha2-256')
      algorithms.instance_variable_set(:@hmac_server, 'hmac-sha2-256')
      algorithms.instance_variable_set(:@compression_client, 'none')
      algorithms.instance_variable_set(:@compression_server, 'none')

      first_result = {
        shared_secret: OpenSSL::BN.new(1234),
        session_id: "initial session id",
        hashing_algorithm: OpenSSL::Digest::SHA256,
        server_key: OpenSSL::PKey::RSA.new(512).public_key,
        server_signature: "initial host signature blob"
      }
      second_result = {
        shared_secret: OpenSSL::BN.new(5678),
        session_id: "rekeyed exchange hash",
        hashing_algorithm: OpenSSL::Digest::SHA256,
        server_key: OpenSSL::PKey::RSA.new(512).public_key,
        server_signature: "rekeyed host signature blob"
      }

      kex = stub
      kex.stubs(:exchange_keys).returns(first_result, second_result)
      Net::SSH::Transport::Kex::DiffieHellmanGroup14SHA256.stubs(:new).returns(kex)
      Net::SSH::Transport::CipherFactory.stubs(:get).returns(stub(implicit_mac?: false))
      Net::SSH::Transport::HMAC.stubs(:get).returns(:hmac)

      algorithms.send(:exchange_keys)
      transport.expect {}
      algorithms.rekey!
      algorithms.send(:exchange_keys)

      assert_equal "initial session id", algorithms.session_id
      assert_equal first_result[:server_key], algorithms.initial_host_key
      assert_equal "initial host signature blob", algorithms.initial_host_signature
      {
        host_key: algorithms.initial_host_key,
        session_id: algorithms.session_id,
        host_signature: algorithms.initial_host_signature
      }
    end

    def run_fake_agent(socket, user_key)
      loop do
        packet = read_packet(socket)
        unless packet
          @agent_error = RuntimeError.new("incomplete packet: #{@agent_buffer.bytes.inspect}")
          break
        end

        body = packet[:body]
        type = packet[:type]
        payload = body.byteslice(1..)
        @recorded << [type, payload.b]
        case type
        when 1
          send_agent_packet(socket, 5)
        when 27
          send_agent_packet(socket, 6)
        when 11
          send_agent_packet(socket, 12,
                            :long, 1,
                            :string, user_key.to_blob,
                            :string, "fake key")
        when 13
          send_agent_packet(socket, 14, :string, "fake signature")
        end
      end
    rescue EOFError, Errno::ENOTCONN, IOError
    rescue Exception => e
      @agent_error = e
    ensure
      socket.close unless socket.closed?
    end

    def read_packet(socket)
      loop do
        if @agent_buffer.length >= 4
          total_length = @agent_buffer.unpack1('N') + 4
          if @agent_buffer.length >= total_length
            frame = @agent_buffer.slice!(0, total_length)
            body = frame.byteslice(4..)
            return { type: body.getbyte(0), body: body }
          end
        end
        readable = IO.select([socket], nil, nil, 0.1)
        next unless readable

        @agent_buffer << socket.readpartial(8192)
      end
    end

    def send_agent_packet(socket, type, *args)
      data = Net::SSH::Buffer.from(*args).to_s
      packet = [data.length + 1, type, data].pack('NCA*')
      socket.send(packet, 0)
    end
  end
end
