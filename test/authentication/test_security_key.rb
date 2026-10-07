require_relative '../common'
require 'net/ssh/authentication/ed25519_loader'
require 'net/ssh/authentication/security_key'
require 'net/ssh/key_factory'

module Authentication
  class TestSecurityKey < NetSSHTest
    APPLICATION = 'ssh:'
    DATA = 'Net::SSH security-key vector'
    FLAGS = 1
    COUNTER = 37

    ED25519_PUBLIC_KEY_LINE = 'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAILJ4LFhJpCq+8cLGSKmyBHrhfuWb4asB/YpyQJm+gRosAAAABHNzaDo= vector'
    ED25519_PUBLIC_KEY = 'b2782c5849a42abef1c2c648a9b2047ae17ee59be1ab01fd8a724099be811a2c'
    ED25519_SIGNATURE = 'cafc189361605a850819e0bd50d8168961ae0f86db842bdb623f4c91f55035cd56201bce127ea60d04d99c5bf49f87146da5b95fa09f39e0d725a8b68432160e'
    ED25519_UV_SIGNATURE = 'be4d0648198937753ef2604f5b79268e867ac4b077538b7898d0202597f66468c40009abd20b89d013d95a93a417375d9f629b5dece959761e7669bff9220c0f'

    ECDSA_PUBLIC_KEY_LINE = 'sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBE4Hoq/7I7wqgDW3FEJE+js62QA7LATe/fEj6aEvdDmSSYUSTa7PvPfiOPvnmrYfT/ezps09p86apyzo15Z4j90AAAAEc3NoOg== vector'
    ECDSA_PUBLIC_KEY = '044e07a2affb23bc2a8035b7144244fa3b3ad9003b2c04defdf123e9a12f7439924985124daecfbcf7e238fbe79ab61f4ff7b3a6cd3da7ce9aa72ce8d796788fdd'
    ECDSA_SIGNATURE = '00000020676d1c7afc24ec690c21ce87c003733b8d26b47a535272ac58508d7a0899c9380000002055bf9d1575dc35ea570b18fafd5d8c4d71a978f85f7bfddf1cd8b341e6c50721'
    ECDSA_UV_SIGNATURE = '0000002100a369f1253c136c6d1efdbf3df4cc176101cb3a16b07af1c1c709887b082b2cc4000000210093dd458a869a2c3cf97a71ddf8a6c2ad924e67180d2a8111c9e811352eea09cf'

    def test_loads_ed25519_security_key_public_key
      skip unless Net::SSH::Authentication::ED25519Loader::LOADED

      key = Net::SSH::KeyFactory.load_data_public_key(ED25519_PUBLIC_KEY_LINE)

      assert_equal 'sk-ssh-ed25519@openssh.com', key.ssh_type
      assert_equal APPLICATION, key.application
      assert_equal binary(ED25519_PUBLIC_KEY), key.public_key_bytes
      assert_round_trips key
    end

    def test_loads_ecdsa_security_key_public_key
      key = Net::SSH::KeyFactory.load_data_public_key(ECDSA_PUBLIC_KEY_LINE)

      assert_equal 'sk-ecdsa-sha2-nistp256@openssh.com', key.ssh_type
      assert_equal APPLICATION, key.application
      assert_equal binary(ECDSA_PUBLIC_KEY), key.public_key_bytes
      assert_round_trips key
    end

    def test_verifies_fixed_ed25519_security_key_signature
      skip unless Net::SSH::Authentication::ED25519Loader::LOADED

      key = Net::SSH::KeyFactory.load_data_public_key(ED25519_PUBLIC_KEY_LINE)

      assert key.ssh_do_verify(security_signature(ED25519_SIGNATURE), DATA)
      refute key.ssh_do_verify(binary(ED25519_SIGNATURE), DATA)
    end

    def test_verifies_fixed_ed25519_security_key_user_verification_signature
      skip unless Net::SSH::Authentication::ED25519Loader::LOADED

      key = Net::SSH::KeyFactory.load_data_public_key(ED25519_PUBLIC_KEY_LINE)

      assert key.ssh_do_verify(security_signature(ED25519_UV_SIGNATURE, flags: 5, counter: 38), DATA)
      refute key.ssh_do_verify(security_signature(ED25519_SIGNATURE, flags: 5, counter: 38), DATA)
    end

    def test_verifies_fixed_ecdsa_security_key_signature
      key = Net::SSH::KeyFactory.load_data_public_key(ECDSA_PUBLIC_KEY_LINE)

      assert key.ssh_do_verify(security_signature(ECDSA_SIGNATURE), DATA)
      refute key.ssh_do_verify(binary(ECDSA_SIGNATURE), DATA)
    end

    def test_verifies_fixed_ecdsa_security_key_user_verification_signature
      key = Net::SSH::KeyFactory.load_data_public_key(ECDSA_PUBLIC_KEY_LINE)

      assert key.ssh_do_verify(security_signature(ECDSA_UV_SIGNATURE, flags: 5, counter: 38), DATA)
      refute key.ssh_do_verify(security_signature(ECDSA_SIGNATURE, flags: 5, counter: 38), DATA)
    end

    def test_rejects_changed_ed25519_security_key_signature_inputs
      skip unless Net::SSH::Authentication::ED25519Loader::LOADED

      key = Net::SSH::KeyFactory.load_data_public_key(ED25519_PUBLIC_KEY_LINE)
      signature = security_signature(ED25519_SIGNATURE)

      refute key.ssh_do_verify(signature, 'changed data')
      refute key.ssh_do_verify(security_signature(ED25519_SIGNATURE, flags: 2), DATA)
      refute key.ssh_do_verify(security_signature(ED25519_SIGNATURE, counter: COUNTER + 1), DATA)

      other_application = Net::SSH::Authentication::SecurityKey::ED25519PubKey.new(
        binary(ED25519_PUBLIC_KEY), 'ssh:other'
      )
      refute other_application.ssh_do_verify(signature, DATA)
    end

    def test_rejects_changed_ecdsa_security_key_signature_inputs
      key = Net::SSH::KeyFactory.load_data_public_key(ECDSA_PUBLIC_KEY_LINE)
      signature = security_signature(ECDSA_SIGNATURE)

      refute key.ssh_do_verify(signature, 'changed data')
      refute key.ssh_do_verify(security_signature(ECDSA_SIGNATURE, flags: 2), DATA)
      refute key.ssh_do_verify(security_signature(ECDSA_SIGNATURE, counter: COUNTER + 1), DATA)

      other_application = Net::SSH::Authentication::SecurityKey::ECDSANistp256PubKey.new(
        binary(ECDSA_PUBLIC_KEY), 'ssh:other'
      )
      refute other_application.ssh_do_verify(signature, DATA)
    end

    def test_request_flags_have_an_explicit_policy
      assert_equal 1, Net::SSH::Authentication::SecurityKey.flags
      assert_equal 0, Net::SSH::Authentication::SecurityKey.flags(0)
      assert_equal 1, Net::SSH::Authentication::SecurityKey.flags(
        Net::SSH::Authentication::SecurityKey::USER_PRESENCE_REQUIRED
      )
      assert_equal 4, Net::SSH::Authentication::SecurityKey.flags(
        Net::SSH::Authentication::SecurityKey::USER_VERIFICATION_REQUIRED
      )
      assert_equal 5, Net::SSH::Authentication::SecurityKey.flags(
        Net::SSH::Authentication::SecurityKey::USER_PRESENCE_REQUIRED |
          Net::SSH::Authentication::SecurityKey::USER_VERIFICATION_REQUIRED
      )

      [2, 8].each do |invalid_flags|
        assert_raises(ArgumentError) do
          Net::SSH::Authentication::SecurityKey.flags(invalid_flags)
        end
      end
    end

    private

    def assert_round_trips(key)
      parsed = Net::SSH::Buffer.new(key.to_blob).read_key

      assert_equal key.ssh_type, parsed.ssh_type
      assert_equal key.to_blob, parsed.to_blob
      assert_equal key.application, parsed.application
    end

    def security_signature(inner_signature, flags: FLAGS, counter: COUNTER)
      Net::SSH::Buffer.from(:byte, flags,
                            :long, counter,
                            :string, binary(inner_signature)).to_s
    end

    def binary(hex)
      [hex].pack('H*')
    end
  end
end
