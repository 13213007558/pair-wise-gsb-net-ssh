require_relative '../common'
require 'net/ssh/service/forward'
require 'socket'

module Connection
  class TestForward < NetSSHTest
    # Simulates the SSH connection: records global requests, lets the test
    # answer them, and dispatches channel-open handlers, so no real server
    # is needed.
    class FakeSession
      attr_accessor :logger
      attr_reader :global_requests, :listeners

      def initialize
        @logger = nil
        @handlers = {}
        @global_requests = []
        @pending_global_request = nil
        @listeners = {}
      end

      def on_open_channel(type, &block)
        @handlers[type] = block
      end

      def open_handler(type)
        @handlers[type]
      end

      def send_global_request(type, *extra, &callback)
        @global_requests << [type, extra]
        @pending_global_request = callback
      end

      def answer_global_request(success, response = nil)
        callback = @pending_global_request
        @pending_global_request = nil
        callback.call(success, response)
      end

      def listen_to(io, &callback)
        @listeners[io] = callback
      end

      def stop_listening_to(io)
        @listeners.delete(io)
      end
    end

    # Simulates an SSH channel: records callbacks registered by the forward
    # service and data sent back towards the server.
    class FakeChannel
      attr_reader :sent_data

      def initialize
        @attributes = {}
        @callbacks = {}
        @sent_data = []
      end

      def [](key)
        @attributes[key]
      end

      def []=(key, value)
        @attributes[key] = value
      end

      def on_data(&block)
        @callbacks[:data] = block
      end

      def on_eof(&block)
        @callbacks[:eof] = block
      end

      def on_close(&block)
        @callbacks[:close] = block
      end

      def on_process(&block)
        @callbacks[:process] = block
      end

      def do_data(data)
        @callbacks[:data].call(self, data)
      end

      def do_eof
        @callbacks[:eof].call(self)
      end

      def do_close
        @callbacks[:close].call(self)
      end

      def do_process
        @callbacks[:process].call(self)
      end

      def send_data(data)
        @sent_data << data
      end

      def close
        @closed = true
      end

      def closed?
        @closed
      end

      def info
      end

      def debug
      end

      def error
      end
    end

    def setup
      @session = FakeSession.new
      @forward = Net::SSH::Service::Forward.new(@session)
      @handler = @session.open_handler('forwarded-streamlocal@openssh.com')
    end

    def test_remote_socket_registers_only_after_success
      @forward.remote_socket('/remote.sock', '/local.sock')

      assert_equal [['streamlocal-forward@openssh.com', [:string, '/remote.sock']]],
                   @session.global_requests
      assert_equal [], @forward.active_remote_sockets

      @session.answer_global_request(true)
      assert_equal ['/remote.sock'], @forward.active_remote_sockets
    end

    def test_remote_socket_requires_a_destination
      assert_raises(ArgumentError) { @forward.remote_socket('/remote.sock') }
      assert_raises(ArgumentError) { @forward.remote_socket('/remote.sock', 'a', 'b', 'c') }
    end

    def test_remote_socket_failure_leaves_no_active_entry
      @forward.remote_socket('/remote.sock', '/local.sock')

      assert_raises(Net::SSH::Exception) do
        @session.answer_global_request(false)
      end
      assert_equal [], @forward.active_remote_sockets
    end

    def test_cancel_remote_socket_removes_entry_on_success
      @forward.remote_socket('/remote.sock', '/local.sock')
      @session.answer_global_request(true)

      @forward.cancel_remote_socket('/remote.sock')
      assert_equal [['streamlocal-forward@openssh.com', [:string, '/remote.sock']],
                    ['cancel-streamlocal-forward@openssh.com', [:string, '/remote.sock']]],
                   @session.global_requests

      # the entry stays active until the server confirms the cancellation
      assert_equal ['/remote.sock'], @forward.active_remote_sockets

      @session.answer_global_request(true)
      assert_equal [], @forward.active_remote_sockets
    end

    def test_cancel_remote_socket_failure_keeps_entry
      @forward.remote_socket('/remote.sock', '/local.sock')
      @session.answer_global_request(true)

      @forward.cancel_remote_socket('/remote.sock')
      assert_raises(Net::SSH::Exception) do
        @session.answer_global_request(false)
      end
      assert_equal ['/remote.sock'], @forward.active_remote_sockets
    end

    def test_connection_accepted_while_cancel_is_in_flight
      register_remote_socket('/remote.sock', '/local.sock')

      @forward.cancel_remote_socket('/remote.sock')

      # a connection arriving before the cancel is confirmed is still
      # accepted and forwarded
      client, server_side = UNIXSocket.pair
      UNIXSocket.expects(:new).with('/local.sock').returns(client)
      channel = open_streamlocal_channel('/remote.sock')
      refute_nil channel[:socket]

      @session.answer_global_request(true)

      # once confirmed, new connections for the path are rejected
      assert_raises(Net::SSH::ChannelOpenFailed) do
        open_streamlocal_channel('/remote.sock')
      end

      channel[:socket].close
      server_side.close
    end

    def test_forwarded_streamlocal_rejects_unknown_path
      error = assert_raises(Net::SSH::ChannelOpenFailed) do
        open_streamlocal_channel('/not-registered.sock')
      end
      assert_equal 1, error.code
    end

    def test_forwarded_streamlocal_to_local_unix_socket
      client, server_side = UNIXSocket.pair
      UNIXSocket.expects(:new).with('/local.sock').returns(client)

      register_remote_socket('/remote.sock', '/local.sock')
      channel = open_streamlocal_channel('/remote.sock')

      # data from the SSH side is forwarded to the local socket
      channel.do_data('from-ssh')
      channel[:socket].send_pending
      assert_equal 'from-ssh', server_side.readpartial(1024)

      # data from the local socket is forwarded to the SSH side
      server_side.write('from-local')
      channel[:socket].fill
      channel.do_process
      assert_equal 'from-local', channel.sent_data.join

      # EOF from the SSH side still flushes already queued data before
      # half-closing the local socket
      channel.do_data('queued-before-eof')
      channel.do_eof
      assert_equal 'queued-before-eof', server_side.readpartial(1024)
      assert_raises(EOFError) { server_side.readpartial(1024) }

      # closing the channel releases the socket and the listener
      channel.do_close
      assert channel[:socket].closed?
      assert_empty @session.listeners

      server_side.close
    end

    def test_forwarded_streamlocal_to_local_tcp_service
      client, server_side = UNIXSocket.pair
      TCPSocket.expects(:new).with('127.0.0.1', 23456).returns(client)

      @forward.remote_socket('/remote-tcp.sock', '127.0.0.1', 23456)
      @session.answer_global_request(true)
      assert_equal ['/remote-tcp.sock'], @forward.active_remote_sockets

      channel = open_streamlocal_channel('/remote-tcp.sock')

      channel.do_data('over-tcp')
      channel[:socket].send_pending
      assert_equal 'over-tcp', server_side.readpartial(1024)

      channel.do_close
      server_side.close
    end

    def test_forwarded_streamlocal_failure_does_not_affect_other_forwards
      register_remote_socket('/a.sock', '/local-a.sock')
      register_remote_socket('/b.sock', '/local-b.sock')

      client_a, server_a_side = UNIXSocket.pair
      UNIXSocket.stubs(:new).with('/local-a.sock').returns(client_a)
      UNIXSocket.stubs(:new).with('/local-b.sock').raises(Errno::ENOENT)

      channel_a = open_streamlocal_channel('/a.sock')

      # a failing connection on /b.sock only fails that channel
      error = assert_raises(Net::SSH::ChannelOpenFailed) do
        open_streamlocal_channel('/b.sock')
      end
      assert_equal 2, error.code

      # the established stream on /a.sock still works
      channel_a.do_data('still-alive')
      channel_a[:socket].send_pending
      assert_equal 'still-alive', server_a_side.readpartial(1024)

      # cancelling /b.sock leaves /a.sock and its stream alone
      @forward.cancel_remote_socket('/b.sock')
      @session.answer_global_request(true)
      assert_equal ['/a.sock'], @forward.active_remote_sockets
      refute channel_a[:socket].closed?

      channel_a.do_data('after-cancel')
      channel_a[:socket].send_pending
      assert_equal 'after-cancel', server_a_side.readpartial(1024)

      channel_a.do_close
      server_a_side.close
    end

    private

    def register_remote_socket(remote_path, *destination)
      @forward.remote_socket(remote_path, *destination)
      @session.answer_global_request(true)
    end

    def open_streamlocal_channel(remote_path)
      channel = FakeChannel.new
      # the leading byte stands in for the message type, which
      # Net::SSH::Packet consumes when the packet is created
      packet = P(:byte, 0, :string, remote_path, :string, '')
      @handler.call(@session, channel, packet)
      channel
    end
  end
end
