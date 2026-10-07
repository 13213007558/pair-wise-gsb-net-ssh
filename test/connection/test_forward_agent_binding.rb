require_relative '../common'
require 'socket'
require 'net/ssh/service/forward'

module Connection
  class TestForwardAgentBinding < NetSSHTest
    def test_forwarded_agent_is_bound_with_forwarding_flag
      assert_forwarding_bind(6, allow_unbound_agent: false)
    end

    def test_unsupported_forwarded_binding_falls_back_when_configured
      assert_forwarding_bind(5, allow_unbound_agent: true)
    end

    def test_unsupported_forwarded_binding_is_rejected_by_default_config
      error = assert_raises(Net::SSH::ChannelOpenFailed) do
        assert_forwarding_bind(28, allow_unbound_agent: true)
      end
      assert_instance_of Net::SSH::Authentication::AgentExtensionFailed, error.cause
    end

    private

    def assert_forwarding_bind(response, options)
      host_key = OpenSSL::PKey::RSA.new(512).public_key
      client, server = UNIXSocket.pair
      packets = []
      buffer = String.new(encoding: Encoding::BINARY)
      thread = Thread.new do
        loop do
          until buffer.length >= 4
            next unless IO.select([server], nil, nil, 0.1)

            buffer << server.readpartial(8192)
          end

          total_length = buffer.unpack1('N') + 4
          until buffer.length >= total_length
            next unless IO.select([server], nil, nil, 0.1)

            buffer << server.readpartial(8192)
          end

          frame = buffer.slice!(0, total_length)
          body = frame.byteslice(4..)

          packets << frame.byteslice(4..)
          type = frame.getbyte(4)
          send_packet(server, type == 27 ? response : 5)
        end
      rescue EOFError, Errno::ENOTCONN, IOError
      ensure
        server.close unless server.closed?
      end

      transport = stub(logger: nil, options: options.merge(agent_socket_factory: -> { client }))
      transport.stubs(:session_binding).returns(
        host_key: host_key,
        session_id: "session",
        host_signature: "signature"
      )
      connection = stub(transport: transport, options: transport.options)
      connection.stubs(:logger).returns(nil)
      connection.stubs(:on_open_channel)
      forward = Net::SSH::Service::Forward.new(connection)
      channel = OpenStruct.new
      connection.stubs(:listen_to)
      connection.stubs(:stop_listening_to)

      forward.send(:auth_agent_channel, connection, channel, stub)
      client.close
      thread.join(1)
      thread.kill

      bind_body = Net::SSH::Buffer.new(packets.find { |packet| packet.getbyte(0) == 27 })
      bind_body.read_byte
      assert_equal Net::SSH::Authentication::Agent::SESSION_BIND_EXTENSION, bind_body.read_string
      assert_equal host_key.to_blob, bind_body.read_string
      assert_equal "session", bind_body.read_string
      assert_equal "signature", bind_body.read_string
      assert_equal true, bind_body.read_bool
    end

    def send_packet(socket, type)
      socket.send([1, type].pack('NC'), 0)
    end
  end
end
