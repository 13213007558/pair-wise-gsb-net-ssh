require_relative '../common'
require 'net/ssh/connection/session'
require 'tempfile'

module Connection
  class TestHostKeyUpdater < NetSSHTest
    include Net::SSH::Connection::Constants

    SESSION_ID = "session-id"
    HOST = "net.ssh.test"
    HOSTKEYS = "hostkeys-00@openssh.com"
    HOSTKEYS_PROVE = "hostkeys-prove-00@openssh.com"

    def test_configuration_modes
      assert_nil Net::SSH::Connection::HostKeyUpdater.mode_for(nil)
      assert_nil Net::SSH::Connection::HostKeyUpdater.mode_for(false)
      assert_equal :append, Net::SSH::Connection::HostKeyUpdater.mode_for(:ask)
      assert_equal :append, Net::SSH::Connection::HostKeyUpdater.mode_for("ask")
      assert_equal :replace, Net::SSH::Connection::HostKeyUpdater.mode_for(true)
      assert_equal :replace, Net::SSH::Connection::HostKeyUpdater.mode_for(:yes)
    end

    def test_append_proven_key_and_preserve_other_entries
      with_host_file("#{HOST} #{line(key1)}", "other.example.com #{line(key2)}") do |file|
        update_with_proof("#{file.path}", :append, [key1, key2])

        assert_equal [key1.ssh_type, key2.ssh_type], hosts(HOST, file.path).map(&:ssh_type)
        assert_equal [key1.to_blob, key2.to_blob], hosts(HOST, file.path).map(&:to_blob)
        assert_equal [key2.to_blob], hosts("other.example.com", file.path).map(&:to_blob)
      end
    end

    def test_replace_removes_retired_key_after_complete_proof
      with_host_file("#{HOST} #{line(key1)}", "other.example.com #{line(key2)}") do |file|
        update_with_proof("#{file.path}", :replace, [key2])

        assert_equal [key2.to_blob], hosts(HOST, file.path).map(&:to_blob)
        assert_equal [key2.to_blob], hosts("other.example.com", file.path).map(&:to_blob)
      end
    end

    def test_invalid_proof_leaves_file_unchanged
      with_host_file("#{HOST} #{line(key1)}") do |file|
        before = File.binread(file.path)
        update_with_proof("#{file.path}", :append, [key1, key2], invalid: true)

        assert_equal before, File.binread(file.path)
      end
    end

    def test_request_failure_leaves_file_unchanged
      with_host_file("#{HOST} #{line(key1)}") do |file|
        before = File.binread(file.path)
        update_with_response(file.path, :append, [key1, key2], Net::SSH::Connection::Constants::REQUEST_FAILURE)

        assert_equal before, File.binread(file.path)
      end
    end

    def test_incomplete_proofs_leave_file_unchanged
      with_host_file("#{HOST} #{line(key1)}") do |file|
        before = File.binread(file.path)
        packet = Net::SSH::Packet.new(
          Net::SSH::Buffer.from(
            :byte, Net::SSH::Connection::Constants::REQUEST_SUCCESS,
            *proof_fields([key1], invalid: false)
          )
        )
        update_with_response(file.path, :append, [key1, key2], nil, packet)

        assert_equal before, File.binread(file.path)
      end
    end

    def test_untrusted_session_does_not_request_proof_or_update_file
      with_host_file("#{HOST} #{line(key1)}") do |file|
        before = File.binread(file.path)
        transport = mock_transport(file.path, trusted: false)
        session = Net::SSH::Connection::Session.new(transport, update_host_keys: :append)

        packet = P(:byte, GLOBAL_REQUEST, :string, HOSTKEYS, :bool, false, *key_blob_fields([key1, key2]))
        transport.queue << packet
        session.send(:dispatch_incoming_packets)

        assert_equal before, File.binread(file.path)
        assert_empty socket.write_buffer
      end
    end

    def test_hashed_entries_stay_hashed_and_new_key_uses_existing_salt
      with_host_file("#{hashed_pattern(HOST)} #{line(key1)}", "other.example.com #{line(key2)}") do |file|
        update_with_proof("#{file.path}", :append, [key1, key2])

        assert_equal 2, hosts(HOST, file.path).count
        assert_equal [key1.to_blob, key2.to_blob], hosts(HOST, file.path).map(&:to_blob)
        assert_equal 2, File.readlines(file.path, chomp: true).count { |entry| entry.start_with?("|1|") }
      end
    end

    def test_non_default_port_pattern_is_preserved
      host = "[#{HOST}]:2222"
      with_host_file("#{host} #{line(key1)}") do |file|
        transport = mock_transport(file.path, host: host)
        session = Net::SSH::Connection::Session.new(transport, update_host_keys: :append)

        run_update(transport, session, [key1, key2])

        assert_equal [key1.to_blob, key2.to_blob], hosts(host, file.path).map(&:to_blob)
        assert File.readlines(file.path, chomp: true).grep(/^\[#{Regexp.escape(HOST)}\]:2222 /).length >= 2
      end
    end

    private

    def key1
      @key1 ||= OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
    end

    def key2
      @key2 ||= OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
    end

    def wrong_key
      @wrong_key ||= OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
    end

    def with_host_file(*lines)
      file = Tempfile.new("known_hosts")
      file.write(lines.join("\n") + "\n")
      file.close
      yield(file)
    ensure
      file&.unlink
    end

    def line(key)
      "#{key.ssh_type} #{encoded(key)}"
    end

    def encoded(key)
      [Net::SSH::Buffer.from(:key, key).to_s].pack("m0")
    end

    def key_blob_fields(keys)
      keys.flat_map { |key| [:raw, key.to_blob] }
    end

    def proof_fields(keys, invalid:)
      blobs = keys.map(&:to_blob)
      keys.flat_map do |key|
        signed_data = Net::SSH::Buffer.from(
          :string, HOSTKEYS,
          :string, SESSION_ID,
          *blobs.flat_map { |blob| [:string, blob] }
        ).to_s
        signing_key = invalid ? wrong_key : key
        signature = signing_key.ssh_do_sign(signed_data, "rsa-sha2-256")
        [:string, Net::SSH::Buffer.from(:string, "rsa-sha2-256", :string, signature).to_s]
      end
    end

    def run_update(transport, session, keys, invalid: false)
      response_packet = nil
      transport.expect do |_socket, packet|
        assert_equal GLOBAL_REQUEST, packet.type
        assert_equal HOSTKEYS_PROVE, packet[:request_type]
        assert_equal true, packet[:want_reply]
        data = packet[:request_data]
        keys.each { |key| assert_equal key.to_blob, data.read_string }

        response_packet ||= Net::SSH::Packet.new(
          Net::SSH::Buffer.from(:byte, REQUEST_SUCCESS, *proof_fields(keys, invalid: invalid))
        )
        transport.queue << response_packet
      end

      transport.queue << P(:byte, GLOBAL_REQUEST, :string, HOSTKEYS, :bool, false, *key_blob_fields(keys))
      session.send(:dispatch_incoming_packets)
      session.send(:dispatch_incoming_packets)
    end

    def update_with_proof(path, mode, keys, invalid: false, host: HOST)
      transport = mock_transport(path, host: host)
      session = Net::SSH::Connection::Session.new(transport, update_host_keys: mode)
      run_update(transport, session, keys, invalid: invalid)
    end

    def update_with_response(path, mode, keys, response_type, response_packet = nil)
      transport = mock_transport(path)
      session = Net::SSH::Connection::Session.new(transport, update_host_keys: mode)
      transport.expect do |_socket, packet|
        assert_equal GLOBAL_REQUEST, packet.type
        transport.queue << (response_packet || P(:byte, response_type))
      end
      transport.queue << P(:byte, GLOBAL_REQUEST, :string, HOSTKEYS, :bool, false, *key_blob_fields(keys))
      session.send(:dispatch_incoming_packets)
      session.send(:dispatch_incoming_packets)
    end

    def mock_transport(path, trusted: true, host: HOST)
      transport = MockTransport.new(socket: socket)
      transport.mock_enqueue = true
      transport.host_as_string = host
      transport.algorithms.session_id = SESSION_ID
      transport.define_singleton_method(:host_keys_trusted?) { trusted }
      transport.define_singleton_method(:host_keys) do
        options = { user_known_hosts_file: path, global_known_hosts_file: [] }
        Net::SSH::HostKeys.new(
          Net::SSH::KnownHosts.search_in(Net::SSH::KnownHosts.hostfiles(options), host, options),
          host,
          Net::SSH::KnownHosts,
          options
        )
      end
      transport
    end

    def hosts(host, path)
      Net::SSH::KnownHosts.new(path).keys_for(host, check_host_ip: false)
    end

    def hashed_pattern(pattern)
      salt = OpenSSL::Random.random_bytes(20)
      digest = OpenSSL::Digest.new("sha1")
      hmac = OpenSSL::HMAC.digest(digest, salt, pattern)
      "|1|#{[salt].pack("m0")}|#{[hmac].pack("m0")}"
    end

    def socket
      @socket ||= begin
        socket = Object.new
        socket.extend(Net::SSH::Transport::PacketStream)
        socket.extend(Module.new do
          def enqueue_packet(message)
            enqueue(message.to_s)
          end
        end)
        socket
      end
    end
  end
end
