require_relative '../common'
require 'net/ssh/test'
require 'socket'
require 'tmpdir'
require 'timeout'

class TestForwardRemoteSocket < NetSSHTest
  include Net::SSH::Test

  def test_remote_socket_registers_only_after_success
    story do |session|
      session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/app.sock")
      session.gets(:request_success)
    end

    assert_scripted do
      yielded = nil
      connection.forward.remote_socket("/tmp/local.sock", "/remote/app.sock") { |path| yielded = path }
      assert_equal [], connection.forward.active_remote_sockets

      connection.loop(0) { connection.forward.active_remote_sockets.empty? }
      assert_equal ["/remote/app.sock"], connection.forward.active_remote_sockets
      assert_equal "/remote/app.sock", yielded
    end
  end

  def test_remote_socket_failure_leaves_no_active_entry
    story do |session|
      session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/app.sock")
      session.gets(:request_failure)
    end

    assert_scripted do
      connection.forward.remote_socket("/tmp/local.sock", "/remote/app.sock")
      assert_raises(Net::SSH::Exception) do
        connection.loop(0) { connection.forward.active_remote_sockets.empty? }
      end
      assert_equal [], connection.forward.active_remote_sockets
    end
  end

  def test_remote_socket_failure_can_be_suppressed_with_block
    story do |session|
      session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/app.sock")
      session.gets(:request_failure)
    end

    assert_scripted do
      yielded = nil
      connection.forward.remote_socket("/tmp/local.sock", "/remote/app.sock") do |result|
        yielded = result
        :no_exception
      end
      connection.loop(0) { yielded.nil? }
      assert_equal :error, yielded
      assert_equal [], connection.forward.active_remote_sockets
    end
  end

  def test_forwarded_streamlocal_for_unknown_path_is_rejected
    story do |session|
      session.gets(:channel_open, "forwarded-streamlocal@openssh.com", 3, 0x20000, 0x8000, "/remote/nope.sock", "")
      session.sends(:channel_open_failure, 3, 1, "unknown request from remote forwarded connection on /remote/nope.sock", "")
    end

    assert_scripted do
      connection.forward
      connection.loop(0) { socket.script.events.any? }
      assert_equal({}, connection.channels)
    end
  end

  def test_cancel_remote_socket_removes_entry_only_after_confirmation
    story do |session|
      session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/app.sock")
      session.gets(:request_success)
      session.sends(:global_request, "cancel-streamlocal-forward@openssh.com", true, "/remote/app.sock")
      session.gets(:request_success)
    end

    assert_scripted do
      connection.forward.remote_socket("/tmp/local.sock", "/remote/app.sock")
      connection.loop(0) { connection.forward.active_remote_sockets.empty? }

      connection.forward.cancel_remote_socket("/remote/app.sock")
      assert_equal ["/remote/app.sock"], connection.forward.active_remote_sockets

      connection.loop(0) { connection.forward.active_remote_sockets.any? }
      assert_equal [], connection.forward.active_remote_sockets
    end
  end

  def test_cancel_remote_socket_failure_keeps_entry
    story do |session|
      session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/app.sock")
      session.gets(:request_success)
      session.sends(:global_request, "cancel-streamlocal-forward@openssh.com", true, "/remote/app.sock")
      session.gets(:request_failure)
    end

    assert_scripted do
      connection.forward.remote_socket("/tmp/local.sock", "/remote/app.sock")
      connection.loop(0) { connection.forward.active_remote_sockets.empty? }

      connection.forward.cancel_remote_socket("/remote/app.sock")
      assert_raises(Net::SSH::Exception) do
        connection.loop(0) { connection.forward.active_remote_sockets.any? }
      end
      assert_equal ["/remote/app.sock"], connection.forward.active_remote_sockets
    end
  end

  if defined?(UNIXServer) && defined?(UNIXSocket)

    # Unix socket paths are severely limited in length (about 100 bytes on
    # most platforms), so keep the path short even when the tmp dir is deep.
    def short_socket_path(name)
      path = File.join(Dir.tmpdir, name)
      path.bytesize <= 100 ? path : name
    end

    def with_unix_server(name)
      path = short_socket_path(name)
      File.delete(path) if File.exist?(path)
      server = UNIXServer.new(path)
      yield server, path
    ensure
      server.close if server
      File.delete(path) if path && File.exist?(path)
    end

    def test_forwarded_streamlocal_forwards_data_and_flushes_on_eof
      with_unix_server("nssh_fwd_data.sock") do |server, local_path|
        story do |session|
          session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/app.sock")
          session.gets(:request_success)
          session.gets(:channel_open, "forwarded-streamlocal@openssh.com", 3, 0x20000, 0x8000, "/remote/app.sock", "")
          session.sends(:channel_open_confirmation, 3, 0, 0x20000, 0x8000)
          session.gets(:channel_data, 0, "hello")
          session.gets(:channel_eof, 0)
          session.gets(:channel_close, 0)
          session.sends(:channel_close, 3)
        end

        assert_scripted do
          received = nil
          reader = Thread.new do
            sock = server.accept
            received = sock.read
            sock.close
          end

          connection.forward.remote_socket(local_path, "/remote/app.sock")
          Timeout.timeout(5) { connection.loop(0) { socket.script.events.any? || connection.channels.any? } }
          reader.join(5)

          assert_equal "hello", received
        end
      end
    end

    def test_forwarded_streamlocal_to_tcp_service
      server = TCPServer.new("127.0.0.1", 0)
      port = server.addr[1]

      story do |session|
        session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/tcp.sock")
        session.gets(:request_success)
        session.gets(:channel_open, "forwarded-streamlocal@openssh.com", 3, 0x20000, 0x8000, "/remote/tcp.sock", "")
        session.sends(:channel_open_confirmation, 3, 0, 0x20000, 0x8000)
        session.gets(:channel_data, 0, "via-tcp")
        session.gets(:channel_eof, 0)
        session.gets(:channel_close, 0)
        session.sends(:channel_close, 3)
      end

      assert_scripted do
        received = nil
        reader = Thread.new do
          sock = server.accept
          received = sock.read
          sock.close
        end

        connection.forward.remote_socket(port, "127.0.0.1", "/remote/tcp.sock")
        Timeout.timeout(5) { connection.loop(0) { socket.script.events.any? || connection.channels.any? } }
        reader.join(5)

        assert_equal "via-tcp", received
      end
    ensure
      server.close if server
    end

    def test_remote_sockets_are_independent
      with_unix_server("nssh_fwd_a.sock") do |server, local_path|
        story do |session|
          session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/a.sock")
          session.gets(:request_success)
          session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/b.sock")
          session.gets(:request_success)

          # a connection on /remote/a.sock is established
          session.gets(:channel_open, "forwarded-streamlocal@openssh.com", 3, 0x20000, 0x8000, "/remote/a.sock", "")
          session.sends(:channel_open_confirmation, 3, 0, 0x20000, 0x8000)

          # a connection on /remote/b.sock fails: nothing listens locally,
          # which must not disturb the established stream of /remote/a.sock
          session.gets(:channel_open, "forwarded-streamlocal@openssh.com", 4, 0x20000, 0x8000, "/remote/b.sock", "")
          session.sends(:channel_open_failure, 4, 2, nil)

          session.gets(:channel_data, 0, "ping")
          session.gets(:channel_eof, 0)
          session.gets(:channel_close, 0)
          session.sends(:channel_close, 3)

          # cancelling /remote/b.sock must not disturb /remote/a.sock either
          session.sends(:global_request, "cancel-streamlocal-forward@openssh.com", true, "/remote/b.sock")
          session.gets(:request_success)
        end

        assert_scripted do
          received = nil
          reader = Thread.new do
            sock = server.accept
            received = sock.read
            sock.close
          end

          connection.forward.remote_socket(local_path, "/remote/a.sock")
          connection.loop(0) { connection.forward.active_remote_sockets.empty? }

          connection.forward.remote_socket("/missing/b.sock", "/remote/b.sock")
          connection.loop(0) { socket.script.events.length > 2 }

          connection.forward.cancel_remote_socket("/remote/b.sock")
          connection.loop(0) { socket.script.events.any? }
          reader.join(5)

          assert_equal "ping", received
          assert_equal ["/remote/a.sock"], connection.forward.active_remote_sockets
        end
      end
    end

    def test_cancel_remote_socket_in_flight_and_established_stream_rules
      with_unix_server("nssh_fwd_inflight.sock") do |server, local_path|
        story do |session|
          session.sends(:global_request, "streamlocal-forward@openssh.com", true, "/remote/app.sock")
          session.gets(:request_success)

          session.sends(:global_request, "cancel-streamlocal-forward@openssh.com", true, "/remote/app.sock")

          # while the cancel is in flight, new channels are still accepted
          session.gets(:channel_open, "forwarded-streamlocal@openssh.com", 3, 0x20000, 0x8000, "/remote/app.sock", "")
          session.sends(:channel_open_confirmation, 3, 0, 0x20000, 0x8000)

          # the cancel is confirmed, but the established stream keeps working
          session.gets(:request_success)
          session.gets(:channel_data, 0, "still-alive")
          session.gets(:channel_eof, 0)
          session.gets(:channel_close, 0)
          session.sends(:channel_close, 3)

          # new channels for the cancelled path are rejected
          session.gets(:channel_open, "forwarded-streamlocal@openssh.com", 4, 0x20000, 0x8000, "/remote/app.sock", "")
          session.sends(:channel_open_failure, 4, 1, nil)
        end

        assert_scripted do
          received = nil
          reader = Thread.new do
            sock = server.accept
            received = sock.read
            sock.close
          end

          connection.forward.remote_socket(local_path, "/remote/app.sock")
          connection.loop(0) { connection.forward.active_remote_sockets.empty? }

          connection.forward.cancel_remote_socket("/remote/app.sock")
          connection.loop(0) { socket.script.events.any? }
          reader.join(5)

          assert_equal "still-alive", received
          assert_equal [], connection.forward.active_remote_sockets
        end
      end
    end
  end
end
