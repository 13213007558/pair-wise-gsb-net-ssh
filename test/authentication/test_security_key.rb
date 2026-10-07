require_relative '../common'
require 'net/ssh/authentication/security_key'
require 'net/ssh/key_factory'
require 'base64'

module Authentication
  # Tests for the OpenSSH security key public key types
  # (sk-ssh-ed25519@openssh.com and sk-ecdsa-sha2-nistp256@openssh.com).
  #
  # All vectors are fixed: they were produced once by signing
  #   string(application) || byte(flags) || uint32(counter) || message
  # with fixed keys, mimicking what a FIDO2 token returns through
  # ssh-agent. The private keys never appear in the library code paths
  # under test, exactly like with real hardware tokens.
  class TestSecurityKey < NetSSHTest
    SK = Net::SSH::Authentication::SecurityKey

    MESSAGE = "net-ssh security key test message\n"
    APPLICATION = "ssh:"

    ED_PUBLIC_BLOB_B64 = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAABHNzaDo="
    ED_PUBLIC_KEY_HEX = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"

    # flags 0x01 (user present), counter 7
    ED_UP_FLAGS = 0x01
    ED_UP_COUNTER = 7
    ED_UP_RAW_B64 = "bnVpo3lCdVR9/JrQs7tsVd/sHCvqf20e74jILQQgFeG8wy9guldBXgfHz8QmkIHA0/OJ3WL3PGkefawbEnE9AQ=="

    # flags 0x05 (user present + user verified), counter 8
    ED_UV_FLAGS = 0x05
    ED_UV_COUNTER = 8
    ED_UV_RAW_B64 = "3DzJ/xLvic8d3D5W9xopyhtTeHICdYj2z1OgIEGtst2DeBZra0WNbT7mq7UIvlTYzkn4T7R4/Nu4gY5NT1z0AQ=="

    # flags 0x04 (user verified, but NOT user present), counter 9
    ED_NO_UP_FLAGS = 0x04
    ED_NO_UP_COUNTER = 9
    ED_NO_UP_RAW_B64 = "z4ZVOJZw/hobDNfDslNmiTSXAMw9a3Qbfet3VWl3FnBXnFaf/HriHTNQU/mgGTE7L6WSg9PDI1ASkXciY86nCA=="

    EC_PUBLIC_BLOB_B64 = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGD+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2eQP+EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpkAAAAEc3NoOg=="
    EC_PUBLIC_OCTETS_HEX = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"

    # flags 0x01 (user present), counter 1037
    EC_UP_FLAGS = 0x01
    EC_UP_COUNTER = 1037
    EC_UP_RAW_B64 = "AAAAIBw7VgAK9ChFMzGhJE0/0dUJbwJ3WlaKBrfLYlwHFfqiAAAAIQCTLDwsUPQy7EXakwW1xvMY36rUvRebHuh1NcTtsKzmNg=="

    def setup
      skip "Ed25519 is not available" unless Net::SSH::Authentication::ED25519Loader::LOADED
    end

    def ed_public_key
      Net::SSH::Buffer.new(Base64.strict_decode64(ED_PUBLIC_BLOB_B64)).read_key
    end

    def ec_public_key
      Net::SSH::Buffer.new(Base64.strict_decode64(EC_PUBLIC_BLOB_B64)).read_key
    end

    def signature_blob(raw_b64, flags, counter, algorithm: nil)
      blob = Net::SSH::Buffer.from(:string, Base64.strict_decode64(raw_b64), :byte, flags, :long, counter).to_s
      algorithm ? Net::SSH::Buffer.from(:mstring, algorithm.dup, :raw, blob).to_s : blob
    end

    def ed_signature(flags: ED_UP_FLAGS, counter: ED_UP_COUNTER, raw_b64: ED_UP_RAW_B64, algorithm: nil)
      signature_blob(raw_b64, flags, counter, algorithm: algorithm)
    end

    def ec_signature(flags: EC_UP_FLAGS, counter: EC_UP_COUNTER, raw_b64: EC_UP_RAW_B64, algorithm: nil)
      signature_blob(raw_b64, flags, counter, algorithm: algorithm)
    end

    def test_algorithm_detection
      assert SK.algorithm?("sk-ssh-ed25519@openssh.com")
      assert SK.algorithm?("sk-ecdsa-sha2-nistp256@openssh.com")
      refute SK.algorithm?("ssh-ed25519")
      refute SK.algorithm?("ecdsa-sha2-nistp256")
      refute SK.algorithm?(nil)
    end

    def test_read_ed25519_public_key_blob
      key = ed_public_key
      assert_instance_of SK::ED25519PubKey, key
      assert_equal "sk-ssh-ed25519@openssh.com", key.ssh_type
      assert_equal "sk-ssh-ed25519@openssh.com", key.ssh_signature_type
      assert_equal APPLICATION, key.application
      assert_equal [ED_PUBLIC_KEY_HEX].pack('H*'), key.public_key_bytes
      assert_equal Base64.strict_decode64(ED_PUBLIC_BLOB_B64), key.to_blob
      assert key.security_key?
      assert_equal "sk-ssh-ed25519@openssh.com #{ED_PUBLIC_BLOB_B64}", key.to_pem
    end

    def test_read_ecdsa_public_key_blob
      key = ec_public_key
      assert_instance_of SK::ECDSAPubKey, key
      assert_equal "sk-ecdsa-sha2-nistp256@openssh.com", key.ssh_type
      assert_equal "sk-ecdsa-sha2-nistp256@openssh.com", key.ssh_signature_type
      assert_equal APPLICATION, key.application
      assert_equal [EC_PUBLIC_OCTETS_HEX].pack('H*'), key.public_key_octets
      assert_equal Base64.strict_decode64(EC_PUBLIC_BLOB_B64), key.to_blob
      assert key.security_key?
      assert_equal "sk-ecdsa-sha2-nistp256@openssh.com #{EC_PUBLIC_BLOB_B64}", key.to_pem
    end

    def test_key_factory_loads_public_keys
      ed = Net::SSH::KeyFactory.load_data_public_key("sk-ssh-ed25519@openssh.com #{ED_PUBLIC_BLOB_B64} token@example")
      assert_instance_of SK::ED25519PubKey, ed
      assert_equal ed_public_key.fingerprint, ed.fingerprint

      ec = Net::SSH::KeyFactory.load_data_public_key("sk-ecdsa-sha2-nistp256@openssh.com #{EC_PUBLIC_BLOB_B64} token@example")
      assert_instance_of SK::ECDSAPubKey, ec
      assert_equal ec_public_key.fingerprint, ec.fingerprint
    end

    def test_ed25519_signature_vector_verifies
      assert_equal true, ed_public_key.ssh_do_verify(ed_signature, MESSAGE)
    end

    def test_ed25519_user_verified_signature_vector_verifies
      assert_equal true, ed_public_key.ssh_do_verify(
        ed_signature(flags: ED_UV_FLAGS, counter: ED_UV_COUNTER, raw_b64: ED_UV_RAW_B64), MESSAGE)
    end

    def test_ecdsa_signature_vector_verifies
      assert_equal true, ec_public_key.ssh_do_verify(ec_signature, MESSAGE)
    end

    def test_signature_parsing_exposes_flags_and_counter
      sig = SK::Signature.parse(ed_signature(flags: ED_UV_FLAGS, counter: ED_UV_COUNTER, raw_b64: ED_UV_RAW_B64))
      assert_equal ED_UV_FLAGS, sig.flags
      assert_equal ED_UV_COUNTER, sig.counter
      assert sig.user_present?
      assert sig.user_verified?
      assert_equal Base64.strict_decode64(ED_UV_RAW_B64), sig.raw_signature
    end

    def test_signature_read_recognizes_agent_style_blob
      blob = ed_signature(algorithm: SK::ALGORITHM_ED25519)
      sig = SK::Signature.read(Net::SSH::Buffer.new(blob))
      assert_equal SK::ALGORITHM_ED25519, sig.algorithm
      assert_equal ED_UP_FLAGS, sig.flags
      assert_equal ED_UP_COUNTER, sig.counter
      assert_equal blob, sig.to_blob
    end

    def test_signature_read_rejects_non_security_key_algorithm
      blob = Net::SSH::Buffer.from(:mstring, "ssh-ed25519".dup, :string, "sig").to_s
      assert_raises(SK::InvalidSignatureError) { SK::Signature.read(Net::SSH::Buffer.new(blob)) }
    end

    def test_signature_parse_rejects_malformed_blobs
      assert_raises(SK::InvalidSignatureError) { SK::Signature.parse("") }
      assert_raises(SK::InvalidSignatureError) { SK::Signature.parse(Net::SSH::Buffer.from(:string, "sig").to_s) }
      assert_raises(SK::InvalidSignatureError) { SK::Signature.parse(ed_signature + "junk") }
    end

    def test_signed_data_includes_application_flags_and_counter
      sig = SK::Signature.parse(ed_signature)
      expected = Net::SSH::Buffer.from(:string, APPLICATION, :byte, ED_UP_FLAGS,
                                       :long, ED_UP_COUNTER, :raw, MESSAGE).to_s
      assert_equal expected, sig.signed_data(APPLICATION, MESSAGE)
    end

    def test_verify_fails_for_wrong_message
      refute ed_public_key.ssh_do_verify(ed_signature, "tampered message")
      refute ec_public_key.ssh_do_verify(ec_signature, "tampered message")
    end

    def test_verify_fails_for_tampered_counter
      refute ed_public_key.ssh_do_verify(ed_signature(counter: ED_UP_COUNTER + 1), MESSAGE)
      refute ec_public_key.ssh_do_verify(ec_signature(counter: EC_UP_COUNTER + 1), MESSAGE)
    end

    def test_verify_fails_for_tampered_flags
      # flipping a flag bit changes the signed data, so verification must fail
      refute ed_public_key.ssh_do_verify(ed_signature(flags: ED_UP_FLAGS | 0x02), MESSAGE)
      refute ec_public_key.ssh_do_verify(ec_signature(flags: EC_UP_FLAGS | 0x02), MESSAGE)
    end

    def test_verify_fails_for_mismatched_application
      ed = SK::ED25519PubKey.new([ED_PUBLIC_KEY_HEX].pack('H*'), "other:")
      refute ed.ssh_do_verify(ed_signature, MESSAGE)

      ec = SK::ECDSAPubKey.new(ec_public_key.public_key, "other:")
      refute ec.ssh_do_verify(ec_signature, MESSAGE)
    end

    def test_raw_signature_does_not_verify_as_plain_signature
      # The security key framing (application, flags, counter) is part of
      # the signed data: stripping it and verifying against the bare
      # message must fail.
      plain_ed = Net::SSH::Authentication::ED25519::PubKey.new([ED_PUBLIC_KEY_HEX].pack('H*'))
      refute plain_ed.ssh_do_verify(Base64.strict_decode64(ED_UP_RAW_B64), MESSAGE)

      plain_ec = ec_public_key.public_key
      refute plain_ec.ssh_do_verify(Base64.strict_decode64(EC_UP_RAW_B64), MESSAGE)
    end

    def test_verify_fails_for_wrong_key
      other = Net::SSH::Authentication::ED25519.new_private_key("\x02" * 32)
      other_pub = SK::ED25519PubKey.new(other.raw_public_key)
      refute other_pub.ssh_do_verify(ed_signature, MESSAGE)
    end

    def test_default_policy_requires_user_presence
      # cryptographically valid signature, but the user-presence flag is
      # not set: the default policy must reject it
      sig = ed_signature(flags: ED_NO_UP_FLAGS, counter: ED_NO_UP_COUNTER, raw_b64: ED_NO_UP_RAW_B64)
      refute ed_public_key.ssh_do_verify(sig, MESSAGE)
    end

    def test_explicit_policy_can_relax_user_presence
      sig = ed_signature(flags: ED_NO_UP_FLAGS, counter: ED_NO_UP_COUNTER, raw_b64: ED_NO_UP_RAW_B64)
      assert_equal true, ed_public_key.ssh_do_verify(sig, MESSAGE, user_presence: :optional)
      assert_equal true, ed_public_key.ssh_do_verify(sig, MESSAGE, user_presence: :forbidden)
    end

    def test_user_verification_requirement
      uv_sig = ed_signature(flags: ED_UV_FLAGS, counter: ED_UV_COUNTER, raw_b64: ED_UV_RAW_B64)
      up_only_sig = ed_signature

      assert_equal true, ed_public_key.ssh_do_verify(uv_sig, MESSAGE, user_verification: :required)
      refute ed_public_key.ssh_do_verify(up_only_sig, MESSAGE, user_verification: :required)
      refute ed_public_key.ssh_do_verify(uv_sig, MESSAGE, user_verification: :forbidden)
    end

    def test_flag_policy_object
      policy = SK::FlagPolicy.new(user_presence: :required, user_verification: :required)
      uv_sig = ed_signature(flags: ED_UV_FLAGS, counter: ED_UV_COUNTER, raw_b64: ED_UV_RAW_B64)
      assert_equal true, ed_public_key.ssh_do_verify(uv_sig, MESSAGE, flag_policy: policy)
      refute ed_public_key.ssh_do_verify(ed_signature, MESSAGE, flag_policy: policy)

      assert policy.allows?(0x05)
      refute policy.allows?(0x01)
      refute SK::DEFAULT_FLAG_POLICY.allows?(0x04)
      assert SK::DEFAULT_FLAG_POLICY.allows?(0x01)
    end

    def test_flag_policy_rejects_invalid_values
      assert_raises(ArgumentError) { SK::FlagPolicy.new(user_presence: :maybe) }
      assert_raises(ArgumentError) { SK::FlagPolicy.new(user_verification: :yes) }
    end

    def test_verify_fails_for_malformed_signature_blobs
      refute ed_public_key.ssh_do_verify("", MESSAGE)
      refute ed_public_key.ssh_do_verify("garbage", MESSAGE)
      refute ec_public_key.ssh_do_verify("", MESSAGE)
      refute ec_public_key.ssh_do_verify("garbage", MESSAGE)
    end

    def test_private_key_blob_raises_clear_error
      buffer = Net::SSH::Buffer.new("")
      error = assert_raises(NotImplementedError) { buffer.read_private_keyblob("sk-ssh-ed25519@openssh.com") }
      assert_match(/ssh-agent/, error.message)
    end
  end
end

require 'net/ssh/authentication/agent'

module Authentication
  # End-to-end tests of the ssh-agent flow with security key identities:
  # the library lists the token's public keys, asks the agent to sign and
  # recognizes the security key signature the agent returns. (The mock
  # agent socket plays the role of the hardware token.)
  class TestSecurityKeyAgent < NetSSHTest
    SK = Net::SSH::Authentication::SecurityKey

    MESSAGE = TestSecurityKey::MESSAGE
    ED_PUBLIC_BLOB = Base64.strict_decode64(TestSecurityKey::ED_PUBLIC_BLOB_B64)
    ED_SIGNATURE_BLOB =
      Net::SSH::Buffer.from(:mstring, SK::ALGORITHM_ED25519.dup,
                            :string, Base64.strict_decode64(TestSecurityKey::ED_UP_RAW_B64),
                            :byte, TestSecurityKey::ED_UP_FLAGS,
                            :long, TestSecurityKey::ED_UP_COUNTER).to_s

    class MockSocket
      def initialize
        @expectation = nil
        @buffer = Net::SSH::Buffer.new
      end

      def expect(&block)
        @expectation = block
      end

      def return(type, *args)
        data = Net::SSH::Buffer.from(*args)
        @buffer.append([data.length + 1, type, data.to_s].pack("NCA*"))
      end

      def send(data, _flags)
        raise "got #{data.inspect} but no packet was expected" unless @expectation

        buffer = Net::SSH::Buffer.new(data)
        buffer.read_long
        type = buffer.read_byte
        @expectation.call(self, type, buffer)
        @expectation = nil
      end

      def read(length)
        @buffer.read(length)
      end
    end

    def setup
      skip "Ed25519 is not available" unless Net::SSH::Authentication::ED25519Loader::LOADED
      @original_ssh_auth_sock, ENV['SSH_AUTH_SOCK'] = ENV['SSH_AUTH_SOCK'], "/path/to/ssh.agent.sock"
      @socket = MockSocket.new
      factory = stub("socket factory", open: @socket)
      @agent = Net::SSH::Authentication::Agent.new
      @agent.stubs(:unix_socket_class).returns(factory)
      @agent.connect!
    end

    def teardown
      ENV['SSH_AUTH_SOCK'] = @original_ssh_auth_sock
    end

    def public_key
      Net::SSH::Buffer.new(ED_PUBLIC_BLOB).read_key
    end

    def test_agent_identities_include_security_keys
      @socket.expect do |s, type, _buffer|
        assert_equal 11, type # SSH2_AGENT_REQUEST_IDENTITIES
        s.return(12, :long, 1, :string, ED_PUBLIC_BLOB, :string, "my hardware token")
      end

      identities = @agent.identities
      assert_equal 1, identities.size
      assert_instance_of SK::ED25519PubKey, identities.first
      assert_equal "my hardware token", identities.first.comment
    end

    def test_agent_sign_returns_recognizable_security_key_signature
      @socket.expect do |s, type, buffer|
        assert_equal 13, type # SSH2_AGENT_SIGN_REQUEST
        assert_equal ED_PUBLIC_BLOB, Net::SSH::Buffer.new(buffer.read_string).read_key.to_blob
        assert_equal MESSAGE, buffer.read_string
        assert_equal 0, buffer.read_long
        s.return(14, :string, ED_SIGNATURE_BLOB) # SSH2_AGENT_SIGN_RESPONSE
      end

      blob = @agent.sign(public_key, MESSAGE)

      signature = SK::Signature.read(Net::SSH::Buffer.new(blob))
      assert_equal SK::ALGORITHM_ED25519, signature.algorithm
      assert signature.user_present?
      assert_equal TestSecurityKey::ED_UP_COUNTER, signature.counter

      remainder = Net::SSH::Buffer.new(blob)
      remainder.read_string
      assert_equal true, public_key.ssh_do_verify(remainder.remainder_as_buffer.to_s, MESSAGE)
    end
  end
end
