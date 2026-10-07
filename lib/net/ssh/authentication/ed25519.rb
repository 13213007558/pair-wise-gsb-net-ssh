require 'openssl'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/authentication/pub_key_fingerprint'

module Net
  module SSH
    module Authentication
      module ED25519
        ALGORITHM = "ED25519"
        KEY_BYTES = 32
        PRIVATE_KEY_BYTES = 64

        class UnsupportedError < StandardError; end

        def self.ensure_supported!
          unless OpenSSL::PKey.respond_to?(:new_raw_public_key) && OpenSSL::PKey.respond_to?(:new_raw_private_key)
            raise UnsupportedError, "OpenSSL::PKey raw public/private key APIs are unavailable"
          end

          key = new_private_key("\x00" * KEY_BYTES)
          signature = sign(key, "")
          public_key = new_public_key(key.raw_public_key)
          raise UnsupportedError, "OpenSSL Ed25519 signature verification failed" unless verify(public_key, signature, "")
        rescue OpenSSL::PKey::PKeyError => e
          raise UnsupportedError, e.message
        end

        def self.new_public_key(key)
          validate_key_bytes!(key, "public key", KEY_BYTES)
          OpenSSL::PKey.new_raw_public_key(ALGORITHM, binary_string(key))
        end

        def self.new_private_key(key)
          validate_key_bytes!(key, "private key", KEY_BYTES)
          OpenSSL::PKey.new_raw_private_key(ALGORITHM, binary_string(key))
        end

        def self.sign(key, data)
          key.sign(nil, data)
        end

        def self.verify(key, signature, data)
          key.verify(nil, signature, data)
        end

        def self.validate_key_bytes!(key, label, expected_bytes)
          raise ArgumentError, "invalid Ed25519 #{label}" unless key.respond_to?(:bytesize) && key.bytesize == expected_bytes
        end

        def self.binary_string(string)
          string.dup.force_encoding('BINARY')
        end
        private_class_method :binary_string

        class OpenSSHPrivateKeyLoader
          CipherFactory = Net::SSH::Transport::CipherFactory

          MBEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
          MEND = "-----END OPENSSH PRIVATE KEY-----"
          MAGIC = "openssh-key-v1"

          class DecryptError < ArgumentError
            def initialize(message, encrypted_key: false)
              super(message)
              @encrypted_key = encrypted_key
            end

            def encrypted_key?
              return @encrypted_key
            end
          end

          def self.read(datafull, password)
            read_all(datafull, password).fetch(0)
          end

          def self.read_all(datafull, password)
            data = decode_container(datafull)
            encrypted = data[:ciphername] != 'none'
            key_material = derive_key_material(data, password, encrypted)
            decoded = decrypt_private_key(
              data[:ciphername],
              data[:encrypted_private],
              data[:auth_tag],
              key: key_material[0...data[:keylen]],
              iv: key_material[data[:keylen]...(data[:keylen] + data[:ivlen])],
              encrypted_key: encrypted
            )

            begin
              entries = decode_private_entries(decoded, data)
            rescue ArgumentError, OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error
              raise unless encrypted
              raise DecryptError.new("Decrypt failed on private key", encrypted_key: true)
            end
            entries
          end

          def self.decode_container(datafull)
            datafull = datafull.to_s.strip
            raise ArgumentError, "Expected #{MBEGIN.strip} header" unless datafull.start_with?(MBEGIN)
            raise ArgumentError, "Expected #{MEND} footer" unless datafull.end_with?(MEND)

            data = datafull[MBEGIN.size...-MEND.size].lines.map(&:strip).join.unpack1("m0")
            raise ArgumentError, "Expected #{MAGIC} at start of decoded private key" unless
              data.start_with?(MAGIC + "\0")

            buffer = Net::SSH::Buffer.new(data.byteslice(MAGIC.bytesize + 1, data.bytesize - MAGIC.bytesize - 1))
            ciphername = read_binary_string(buffer, "cipher name")
            supported_cipher =
              begin
                CipherFactory.supported?(ciphername)
              rescue StandardError
                false
              end
            raise ArgumentError, "#{ciphername} in private key is not supported" unless supported_cipher

            kdfname = read_binary_string(buffer, "KDF name")
            raise ArgumentError, "Expected KDF name to be none or bcrypt" unless %w[none bcrypt].include?(kdfname)

            kdfoptions = Net::SSH::Buffer.new(read_binary_string(buffer, "KDF options"))
            num_keys = buffer.read_long
            raise ArgumentError, "Private key container does not contain any keys" unless num_keys && num_keys > 0

            public_keys = Array.new(num_keys) do
              public_key = read_binary_string(buffer, "public key")
              {
                blob: public_key,
                buffer: Net::SSH::Buffer.new(public_key)
              }
            end

            encrypted_length = buffer.read_long
            keylen, blocksize, ivlen = CipherFactory.get_lengths(ciphername, iv_len: true)
            if encrypted_length.nil? || encrypted_length < blocksize ||
               (blocksize > 0 && encrypted_length % blocksize != 0)
              raise ArgumentError, "Private key length is not a multiple of #{blocksize}"
            end

            encrypted_private = read_exactly(buffer, encrypted_length, "encrypted private section")
            auth_length = CipherFactory.auth_length(ciphername)
            auth_tag = auth_length > 0 ? read_exactly(buffer, auth_length, "authentication tag") : nil
            raise ArgumentError, "Unexpected data after private key container" unless buffer.eof?

            {
              ciphername: ciphername,
              kdfname: kdfname,
              kdfoptions: kdfoptions,
              public_keys: public_keys,
              encrypted_private: encrypted_private,
              encrypted_length: encrypted_length,
              blocksize: blocksize,
              auth_tag: auth_tag,
              keylen: keylen,
              ivlen: ivlen
            }
          end

          def self.derive_key_material(data, password, encrypted)
            if data[:kdfname] == 'none'
              raise ArgumentError, "Encrypted private key must use bcrypt KDF" if encrypted
              return "\x00".b * (data[:keylen] + data[:ivlen])
            end

            raise ArgumentError, "Unencrypted private key must use none KDF" unless encrypted
            salt = read_binary_string(data[:kdfoptions], "KDF salt")
            rounds = data[:kdfoptions].read_long
            raise ArgumentError, "Invalid KDF options" if rounds.nil? || !data[:kdfoptions].eof?
            raise DecryptError.new("Decrypt failed on private key", encrypted_key: true) unless rounds > 0

            bcrypt_pbkdf_key(password, salt, data[:keylen] + data[:ivlen], rounds)
          end

          def self.decode_private_entries(decoded, container)
            buffer = Net::SSH::Buffer.new(decoded)
            check1 = buffer.read_long
            check2 = buffer.read_long
            raise ArgumentError, "Invalid private key check values" unless
              check1 && check2 && check1 == check2

            keys = container[:public_keys].map do |public_key|
              type_name = read_binary_string(buffer, "private key type")
              outer_type = read_binary_string(public_key[:buffer], "public key type")
              key = read_private_key(buffer, type_name)
              unless key.to_blob == public_key[:blob] && type_name == outer_type
                raise ArgumentError, "Private key does not match public key"
              end

              key.comment = read_binary_string(buffer, "key comment")
              key
            end

            padding_block_size = container[:blocksize].zero? ? 8 : container[:blocksize]
            entries_length = buffer.position
            padding_length = padding_block_size - (entries_length % padding_block_size)
            padding_length = 0 if padding_length == padding_block_size
            padding = read_exactly(buffer, padding_length, "private key padding")
            padding.each_byte.with_index do |byte, index|
              raise ArgumentError, "Invalid private key padding" unless byte == (index + 1) % 256
            end
            raise ArgumentError, "Unexpected data after private key entries" unless buffer.eof?
            keys
          end

          def self.read_private_key(buffer, type_name)
            case type_name
            when 'ssh-ed25519'
              PrivKey.new(buffer)
            when 'ssh-rsa'
              read_rsa_private_key(buffer)
            when 'ssh-dss'
              read_dsa_private_key(buffer)
            when /\Aecdsa-sha2-(nistp\d+)\z/
              read_ecdsa_private_key(buffer, $1)
            else
              raise ArgumentError, "Cannot decode private key of type #{type_name}"
            end
          rescue OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error, OpenSSL::BNError,
                 OpenSSL::PKey::EC::Point::Error, TypeError, NoMethodError
            raise ArgumentError, "Invalid #{type_name} private key"
          end

          def self.read_rsa_private_key(buffer)
            n, e, d, iqmp, p, q = 6.times.map { read_bignum(buffer) }
            raise ArgumentError, "Invalid RSA private key" unless
              [n, e, d, iqmp, p, q].all? { |number| number > 0 } &&
              e < n && d < n && p < n && q < n &&
              n == p * q &&
              (q * iqmp) % p == 1 &&
              (e * d) % rsa_lambda(p, q) == 1

            dmp1 = d % (p - 1)
            dmq1 = d % (q - 1)
            asn1 = OpenSSL::ASN1::Sequence.new([
                                               OpenSSL::ASN1::Integer.new(0),
                                               OpenSSL::ASN1::Integer.new(n),
                                               OpenSSL::ASN1::Integer.new(e),
                                               OpenSSL::ASN1::Integer.new(d),
                                               OpenSSL::ASN1::Integer.new(p),
                                               OpenSSL::ASN1::Integer.new(q),
                                               OpenSSL::ASN1::Integer.new(dmp1),
                                               OpenSSL::ASN1::Integer.new(dmq1),
                                               OpenSSL::ASN1::Integer.new(iqmp)
                                             ])
            build_key(OpenSSL::PKey::RSA, asn1)
          end

          def self.read_dsa_private_key(buffer)
            p, q, g, public_number, private_number = 5.times.map { read_bignum(buffer) }
            raise ArgumentError, "Invalid DSA private key" unless
              [p, q, g, public_number, private_number].all? { |number| number > 0 } &&
              private_number < q &&
              public_number < p &&
              public_number == g.mod_exp(private_number, p)

            asn1 = OpenSSL::ASN1::Sequence.new([
                                               OpenSSL::ASN1::Integer.new(0),
                                               OpenSSL::ASN1::Integer.new(p),
                                               OpenSSL::ASN1::Integer.new(q),
                                               OpenSSL::ASN1::Integer.new(g),
                                               OpenSSL::ASN1::Integer.new(public_number),
                                               OpenSSL::ASN1::Integer.new(private_number)
                                             ])
            build_key(OpenSSL::PKey::DSA, asn1)
          end

          def self.read_ecdsa_private_key(buffer, curve_name)
            key_curve_name = read_binary_string(buffer, "ECDSA curve name")
            public_point = read_binary_string(buffer, "ECDSA public point")
            encoded_private_scalar = read_binary_string(buffer, "ECDSA private scalar")
            raise ArgumentError, "ECDSA curve name does not match key type" unless curve_name == key_curve_name

            group = OpenSSL::PKey::EC::Group.new(OpenSSL::PKey::EC::CurveNameAlias.fetch(curve_name))
            expected_length = (group.degree + 7) / 8
            point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(public_point, 2))
            private_scalar = encoded_private_scalar[-expected_length, expected_length].to_s
            scalar_value = OpenSSL::BN.new(private_scalar, 2)
            order = group.order
            raise ArgumentError, "Invalid ECDSA private key" unless
              [expected_length, expected_length + 1].include?(encoded_private_scalar.bytesize) &&
                scalar_value > 0 && scalar_value < order &&
                point == group.generator.mul(scalar_value) &&
                public_point.bytesize == 1 + 2 * expected_length

            asn1 = OpenSSL::ASN1::Sequence.new([
                                               OpenSSL::ASN1::Integer.new(1),
                                               OpenSSL::ASN1::OctetString.new(private_scalar),
                                               OpenSSL::ASN1::ASN1Data.new(
                                                 [OpenSSL::ASN1::ObjectId.new(group.curve_name)], 0, :CONTEXT_SPECIFIC
                                               ),
                                               OpenSSL::ASN1::ASN1Data.new(
                                                 [OpenSSL::ASN1::BitString.new(public_point)], 1, :CONTEXT_SPECIFIC
                                               )
                                             ])
            key = build_key(OpenSSL::PKey::EC, asn1)
            raise ArgumentError, "Invalid ECDSA private key" unless key.private? && key.check_key
            key
          end

          def self.read_binary_string(buffer, description)
            string = buffer.read_string
            raise ArgumentError, "Missing #{description}" if string.nil?
            binary_string(string)
          end

          def self.read_exactly(buffer, length, description)
            data = buffer.read(length)
            raise ArgumentError, "Missing #{description}" unless data&.bytesize == length
            binary_string(data)
          end

          def self.read_bignum(buffer)
            number = buffer.read_bignum
            raise ArgumentError, "Missing private key bignum" if number.nil?
            number
          end

          def self.build_key(klass, asn1)
            key = klass.new(asn1.to_der)
            raise ArgumentError, "Invalid private key" unless key.private?
            key
          end

          def self.rsa_lambda(p, q)
            p_minus_one = p - 1
            q_minus_one = q - 1
            p_minus_one.to_i.lcm(q_minus_one.to_i)
          end

          def self.binary_string(string)
            string.to_s.dup.force_encoding('BINARY')
          end

          def self.bcrypt_pbkdf_key(password, salt, length, rounds)
            begin
              require_bcrypt_pbkdf
            rescue LoadError
              raise DecryptError.new("bcrypt_pbkdf is required to decrypt bcrypt-encrypted OpenSSH private keys")
            end

            key = BCryptPbkdf::key(password, salt, length, rounds)
            raise DecryptError.new("BCryptPbkdf failed", encrypted_key: true) unless key
            binary_string(key)
          rescue DecryptError
            raise
          rescue ArgumentError
            raise DecryptError.new("BCryptPbkdf failed", encrypted_key: true)
          end

          def self.require_bcrypt_pbkdf
            require 'bcrypt_pbkdf'
          end

          def self.decrypt_private_key(ciphername, encrypted_private, auth_tag, options)
            if auth_tag
              return CipherFactory.decrypt_private_key(
                ciphername,
                encrypted_private,
                auth_tag,
                options[:key],
                options[:iv]
              )
            end

            cipher = CipherFactory.get(ciphername, key: options[:key], iv: options[:iv], decrypt: true)
            decoded = cipher.update(encrypted_private)
            decoded << cipher.final
          rescue Net::SSH::Exception, OpenSSL::Cipher::CipherError
            raise DecryptError.new("Decrypt failed on private key", encrypted_key: options[:encrypted_key])
          end
        end

        class PubKey
          include Net::SSH::Authentication::PubKeyFingerprint

          def initialize(data)
            ED25519.validate_key_bytes!(data, "public key", KEY_BYTES)
            @public_key_bytes = data.dup.force_encoding('BINARY')
          end

          def self.read_keyblob(buffer)
            PubKey.new(buffer.read_string)
          end

          def to_blob
            Net::SSH::Buffer.from(:mstring, "ssh-ed25519".dup, :string, public_key_bytes).to_s
          end

          def ssh_type
            "ssh-ed25519"
          end

          def ssh_signature_type
            ssh_type
          end

          def ssh_do_verify(sig, data, options = {})
            ED25519.verify(verify_key, sig, data)
          end

          def to_pem
            # TODO this is not pem
            ssh_type + [public_key_bytes].pack("m")
          end

          def public_key_bytes
            @public_key_bytes.dup
          end

          def verify_key
            @verify_key ||= ED25519.new_public_key(@public_key_bytes)
          end
        end

        class PrivKey
          CipherFactory = Net::SSH::Transport::CipherFactory

          attr_reader :sign_key
          attr_accessor :comment

          def initialize(buffer)
            pk = buffer.read_string
            sk = buffer.read_string

            ED25519.validate_key_bytes!(pk, "public key", KEY_BYTES)
            ED25519.validate_key_bytes!(sk, "private key field", PRIVATE_KEY_BYTES)

            private_key_bytes = sk[0, KEY_BYTES]
            raise ArgumentError, "Ed25519 private key does not include matching public key" unless sk[KEY_BYTES, KEY_BYTES] == pk

            @sign_key = ED25519.new_private_key(private_key_bytes)
            raise ArgumentError, "Ed25519 public key does not match private key" unless @sign_key.raw_public_key == pk

            @public_key_bytes = pk.dup.force_encoding('BINARY')
            @private_key_bytes = private_key_bytes.dup.force_encoding('BINARY')
          end

          def to_blob
            public_key.to_blob
          end

          def ssh_type
            "ssh-ed25519"
          end

          def ssh_signature_type
            ssh_type
          end

          def public_key
            PubKey.new(public_key_bytes)
          end

          def ssh_do_sign(data, sig_alg = nil)
            ED25519.sign(@sign_key, data)
          end

          def public_key_bytes
            @public_key_bytes.dup
          end

          def private_key_bytes
            @private_key_bytes.dup
          end

          def private_key_bytes_for_agent
            private_key_bytes + public_key_bytes
          end

          def self.read(data, password)
            OpenSSHPrivateKeyLoader.read(data, password)
          end
        end
      end
    end
  end
end
