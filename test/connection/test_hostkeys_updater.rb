require_relative '../common'
require 'net/ssh/connection/session'
require 'tempfile'

module Connection
  class TestHostKeysUpdater < NetSSHTest
    include Net::SSH::Connection::Constants

    REQUEST = Net::SSH::Connection::HostKeysUpdater::REQUEST
    PROVE_REQUEST = Net::SSH::Connection::HostKeysUpdater::PROVE_REQUEST
    SESSION_ID = 'abcxyz123'

    module MockSocket
      # so that we can easily test the contents that were enqueued, without
      # worrying about all the packet stream overhead
      def enqueue_packet(message)
        enqueue(message.to_s)
      end
    end

    def setup
      @socket = @transport = @session = nil
      @file = Tempfile.open('known_hosts')
      @file.close
    end

    def teardown
      @file.close!
    end

    def test_ignores_advertisement_when_session_is_not_trusted
      seed_known_hosts(host_entry(current_key))
      transport.host_key_trusted = false

      send_hostkeys(current_key, new_key)

      assert_equal '', socket.write_buffer
      assert_equal [host_entry(current_key)], known_hosts_lines
    end

    def test_ignores_advertisement_when_option_disabled
      seed_known_hosts(host_entry(current_key))
      @session = Net::SSH::Connection::Session.new(transport, options(update_host_keys: false))
      transport.host_key_trusted = true

      send_hostkeys(current_key, new_key)

      assert_equal '', socket.write_buffer
      assert_equal [host_entry(current_key)], known_hosts_lines
    end

    def test_append_mode_learns_proven_new_key
      seed_known_hosts(host_entry(current_key), host_entry(other_key, 'other.example.com'))
      transport.host_key_trusted = true

      send_hostkeys(current_key, new_key)
      assert_equal prove_packet(new_key).to_s, socket.write_buffer

      reply_prove(prove_signature(new_key))

      assert_equal [
        host_entry(current_key),
        host_entry(other_key, 'other.example.com'),
        host_entry(new_key)
      ], known_hosts_lines
    end

    def test_append_mode_keeps_retired_keys
      seed_known_hosts(host_entry(current_key), host_entry(retired_key))
      transport.host_key_trusted = true

      send_hostkeys(current_key)

      assert_equal '', socket.write_buffer
      assert_equal [host_entry(current_key), host_entry(retired_key)], known_hosts_lines
    end

    def test_sync_mode_removes_retired_keys_after_proof
      seed_known_hosts(host_entry(current_key), host_entry(retired_key), host_entry(other_key, 'other.example.com'))
      session(update_host_keys: :sync)
      transport.host_key_trusted = true

      send_hostkeys(current_key, new_key)
      assert_equal prove_packet(new_key).to_s, socket.write_buffer

      reply_prove(prove_signature(new_key))

      assert_equal [
        host_entry(current_key),
        host_entry(other_key, 'other.example.com'),
        host_entry(new_key)
      ], known_hosts_lines
    end

    def test_sync_mode_removes_retired_keys_without_new_keys
      seed_known_hosts(host_entry(current_key), host_entry(retired_key))
      session(update_host_keys: :sync)
      transport.host_key_trusted = true

      send_hostkeys(current_key)

      assert_equal '', socket.write_buffer
      assert_equal [host_entry(current_key)], known_hosts_lines
    end

    def test_failed_proof_leaves_known_hosts_untouched
      seed_known_hosts(host_entry(current_key), host_entry(retired_key))
      session(update_host_keys: :sync)
      transport.host_key_trusted = true
      before = File.read(@file.path)

      send_hostkeys(current_key, new_key)
      reply_prove(prove_signature(retired_key))

      assert_equal before, File.read(@file.path)
    end

    def test_request_failure_leaves_known_hosts_untouched
      seed_known_hosts(host_entry(current_key), host_entry(retired_key))
      session(update_host_keys: :sync)
      transport.host_key_trusted = true
      before = File.read(@file.path)

      send_hostkeys(current_key, new_key)
      session.send(:request_failure, P(:byte, REQUEST_FAILURE))

      assert_equal before, File.read(@file.path)
    end

    def test_missing_signature_leaves_known_hosts_untouched
      seed_known_hosts(host_entry(current_key))
      transport.host_key_trusted = true
      before = File.read(@file.path)

      send_hostkeys(current_key, new_key)
      session.send(:request_success, P(:byte, REQUEST_SUCCESS))

      assert_equal before, File.read(@file.path)
    end

    def test_rsa_key_proven_with_rsa_sha2_signature
      seed_known_hosts(host_entry(current_key))
      transport.host_key_trusted = true

      send_hostkeys(current_key, rsa_key)
      assert_equal prove_packet(rsa_key).to_s, socket.write_buffer

      reply_prove(prove_signature(rsa_key, 'rsa-sha2-512'))

      assert_equal [host_entry(current_key), host_entry(rsa_key)], known_hosts_lines
    end

    def test_garbage_and_unknown_blobs_are_ignored
      seed_known_hosts(host_entry(current_key))
      transport.host_key_trusted = true

      args = [:byte, GLOBAL_REQUEST, :string, REQUEST, :bool, false,
              :string, 'rubbish', :string, key_blob(new_key)]
      session.send(:global_request, P(*args))

      assert_equal prove_packet(new_key).to_s, socket.write_buffer
    end

    def test_sync_mode_updates_hashed_entries
      seed_known_hosts(hashed_entry('net.ssh.test', current_key),
                       hashed_entry('net.ssh.test', retired_key),
                       hashed_entry('other.example.com', retired_key))
      session(update_host_keys: :sync)
      transport.host_key_trusted = true

      send_hostkeys(current_key, new_key)
      reply_prove(prove_signature(new_key))

      assert_equal [
        hashed_entry('net.ssh.test', current_key),
        hashed_entry('other.example.com', retired_key),
        host_entry(new_key)
      ], known_hosts_lines
    end

    def test_sync_mode_handles_non_default_port
      transport.host_as_string = '[net.ssh.test]:2222'
      seed_known_hosts(host_entry(current_key, '[net.ssh.test]:2222'),
                       host_entry(retired_key, '[net.ssh.test]:2222'))
      session(update_host_keys: :sync)
      transport.host_key_trusted = true

      send_hostkeys(current_key, new_key)
      reply_prove(prove_signature(new_key))

      assert_equal [
        host_entry(current_key, '[net.ssh.test]:2222'),
        host_entry(new_key, '[net.ssh.test]:2222')
      ], known_hosts_lines
    end

    def test_repeated_advertisement_does_not_duplicate_entries
      seed_known_hosts(host_entry(current_key))
      transport.host_key_trusted = true

      send_hostkeys(current_key, new_key)
      reply_prove(prove_signature(new_key))
      assert_equal [host_entry(current_key), host_entry(new_key)], known_hosts_lines

      send_hostkeys(current_key, new_key)

      assert_equal prove_packet(new_key).to_s, socket.write_buffer
      assert_equal [host_entry(current_key), host_entry(new_key)], known_hosts_lines
    end

    private

    def options(extra = {})
      { update_host_keys: true,
        user_known_hosts_file: @file.path,
        global_known_hosts_file: [] }.merge(extra)
    end

    def socket
      @socket ||= begin
        socket = Object.new
        socket.extend(Net::SSH::Transport::PacketStream)
        socket.extend(MockSocket)
        socket
      end
    end

    def transport(extra = {})
      @transport ||= MockTransport.new(options(extra).merge(socket: socket))
    end

    def session(extra = {})
      @session ||= Net::SSH::Connection::Session.new(transport(extra), options(extra))
    end

    def current_key
      @current_key ||= OpenSSL::PKey::EC.generate('prime256v1')
    end

    def new_key
      @new_key ||= OpenSSL::PKey::EC.generate('prime256v1')
    end

    def retired_key
      @retired_key ||= OpenSSL::PKey::EC.generate('prime256v1')
    end

    def other_key
      @other_key ||= OpenSSL::PKey::EC.generate('prime256v1')
    end

    def rsa_key
      @rsa_key ||= OpenSSL::PKey::RSA.generate(2048)
    end

    def key_blob(key)
      Net::SSH::Buffer.from(:key, key).to_s
    end

    def host_entry(key, host = 'net.ssh.test,127.0.0.1')
      blob = [key_blob(key)].pack('m*').gsub(/\s/, '')
      "#{host} #{key.ssh_type} #{blob}"
    end

    def hashed_entry(hostname, key, salt = '0123456789abcdefghij')
      digest = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha1'), salt, hostname)
      token = "|1|#{[salt].pack('m*').gsub(/\s/, '')}|#{[digest].pack('m*').gsub(/\s/, '')}"
      blob = [key_blob(key)].pack('m*').gsub(/\s/, '')
      "#{token} #{key.ssh_type} #{blob}"
    end

    def seed_known_hosts(*entries)
      File.write(@file.path, entries.join("\n") + "\n")
    end

    def known_hosts_lines
      File.read(@file.path).split("\n")
    end

    def send_hostkeys(*keys)
      args = [:byte, GLOBAL_REQUEST, :string, REQUEST, :bool, false]
      keys.each { |key| args += [:string, key_blob(key)] }
      session.send(:global_request, P(*args))
    end

    def prove_packet(*keys)
      args = [:byte, GLOBAL_REQUEST, :string, PROVE_REQUEST, :bool, true]
      keys.each { |key| args += [:string, key_blob(key)] }
      P(*args)
    end

    def prove_signature(key, sig_type = nil)
      sig_type ||= key.ssh_type
      data = Net::SSH::Buffer.from(:string, PROVE_REQUEST, :string, SESSION_ID, :string, key_blob(key)).to_s
      sig = key.ssh_do_sign(data, sig_type)
      Net::SSH::Buffer.from(:string, sig_type, :string, sig).to_s
    end

    def reply_prove(*signatures)
      args = [:byte, REQUEST_SUCCESS]
      signatures.each { |sig| args += [:string, sig] }
      session.send(:request_success, P(*args))
    end
  end
end
