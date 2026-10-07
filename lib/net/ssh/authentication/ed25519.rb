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

          # Reads the first private key from an openssh-key-v1 container.
          # Raises if the container holds no usable key.
          def self.read(datafull, password)
            read_all(datafull, password).first
          end

          # Reads every private key stored in an openssh-key-v1 container.
          # Returns an array of keys in container order; each key responds to
          # +comment+ with the comment stored alongside it. Raises if the
          # container is malformed, truncated, or cannot be decrypted with
          # the given password.
          def self.read_all(datafull, password)
            datafull = datafull.strip
            raise ArgumentError.new("Expected #{MBEGIN} at start of private key") unless datafull.start_with?(MBEGIN)
            raise ArgumentError.new("Expected #{MEND} at end of private key") unless datafull.end_with?(MEND)

            datab64 = datafull[MBEGIN.size...-MEND.size]
            data = datab64.unpack1("m")
            raise ArgumentError.new("Expected #{MAGIC} at start of decoded private key") unless data.start_with?(MAGIC)

            buffer = Net::SSH::Buffer.new(data[(MAGIC.size + 1)..-1])

            ciphername = read_string_fully(buffer, "cipher name")
            raise ArgumentError.new("#{ciphername} in private key is not supported") unless
              CipherFactory.supported?(ciphername)

            kdfname = read_string_fully(buffer, "kdf name")
            raise ArgumentError.new("Expected #{kdfname} to be or none or bcrypt") unless %w[none bcrypt].include?(kdfname)

            kdfopts = Net::SSH::Buffer.new(read_string_fully(buffer, "kdf options"))
            num_keys = read_long_fully(buffer, "key count")
            raise ArgumentError.new("No keys found in private key") if num_keys < 1

            public_keys = Array.new(num_keys) { read_string_fully(buffer, "public key") }

            len = read_long_fully(buffer, "private key block length")
            encrypted_private = read_fully(buffer, len, "private key block")

            keylen, blocksize, ivlen = CipherFactory.get_lengths(ciphername, iv_len: true)
            raise ArgumentError.new("Private key len:#{len} is not a multiple of #{blocksize}") if
              (len < blocksize) || ((blocksize > 0) && (len % blocksize) != 0)

            authlen = CipherFactory.auth_length(ciphername)
            auth_tag = authlen > 0 ? read_fully(buffer, authlen, "auth tag") : nil

            encrypted_key = (kdfname == 'bcrypt')
            if encrypted_key
              salt = read_string_fully(kdfopts, "kdf salt")
              rounds = read_long_fully(kdfopts, "kdf rounds")

              key = bcrypt_pbkdf_key(password, salt, keylen + ivlen, rounds)
            else
              key = "\x00" * (keylen + ivlen)
            end

            decoded = decrypt_private_key(
              ciphername,
              encrypted_private,
              auth_tag,
              key: key[0...keylen],
              iv: key[keylen...(keylen + ivlen)],
              encrypted_key: encrypted_key
            )

            decoded = Net::SSH::Buffer.new(decoded)
            check1 = read_long_fully(decoded, "checkint", encrypted_key)
            check2 = read_long_fully(decoded, "checkint", encrypted_key)

            raise DecryptError.new("Decrypt failed on private key", encrypted_key: encrypted_key) if (check1 != check2)

            keys = Array.new(num_keys) do |index|
              key = read_private_key(decoded, encrypted_key)
              unless key.to_blob == public_keys[index]
                raise DecryptError.new("Public key does not match private key", encrypted_key: encrypted_key)
              end
              key
            end

            verify_padding!(decoded, encrypted_key)

            keys
          end

          def self.bcrypt_pbkdf_key(password, salt, length, rounds)
            begin
              require_bcrypt_pbkdf
            rescue LoadError
              raise DecryptError.new("bcrypt_pbkdf is required to decrypt bcrypt-encrypted OpenSSH private keys")
            end

            key = BCryptPbkdf::key(password, salt, length, rounds)
            raise DecryptError.new("BCryptPbkdf failed", encrypted_key: true) unless key

            key
          end

          def self.read_private_key(decoded, encrypted_key)
            type_name = read_string_fully(decoded, "key type", encrypted_key)
            case type_name
            when "ssh-ed25519"
              PrivKey.new(decoded)
            else
              key = decoded.read_private_keyblob(type_name)
              comment = read_string_fully(decoded, "key comment", encrypted_key)
              attach_comment(key, comment)
            end
          rescue ArgumentError => e
            raise if e.is_a?(DecryptError)

            raise DecryptError.new("Failed to parse private key", encrypted_key: encrypted_key)
          end
          private_class_method :read_private_key

          def self.attach_comment(key, comment)
            key.instance_variable_set(:@comment, comment)
            key.define_singleton_method(:comment) { @comment }
            key
          end
          private_class_method :attach_comment

          def self.verify_padding!(decoded, encrypted_key)
            padding = decoded.read(decoded.length - decoded.position) || ""
            expected = (1..padding.bytesize).map { |i| i % 256 }.pack("C*")
            unless padding == expected
              raise DecryptError.new("Decrypt failed on private key", encrypted_key: encrypted_key)
            end
          end
          private_class_method :verify_padding!

          def self.read_string_fully(buffer, description, encrypted_key = nil)
            length = read_long_fully(buffer, description, encrypted_key)
            read_fully(buffer, length, description, encrypted_key)
          end

          def self.read_long_fully(buffer, description, encrypted_key = nil)
            read_fully(buffer, 4, description, encrypted_key).unpack1("N")
          end

          def self.read_fully(buffer, count, description, encrypted_key = nil)
            if buffer.length - buffer.position < count
              message = "Truncated private key: missing #{description}"
              if encrypted_key.nil?
                raise ArgumentError, message
              else
                raise DecryptError.new(message, encrypted_key: encrypted_key)
              end
            end
            buffer.read(count)
          end
          private_class_method :read_string_fully, :read_long_fully, :read_fully

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
          attr_reader :comment

          def initialize(buffer)
            pk = buffer.read_string
            sk = buffer.read_string
            comment = buffer.read_string

            ED25519.validate_key_bytes!(pk, "public key", KEY_BYTES)
            ED25519.validate_key_bytes!(sk, "private key field", PRIVATE_KEY_BYTES)
            raise ArgumentError, "Ed25519 private key is missing its comment" if comment.nil?

            private_key_bytes = sk[0, KEY_BYTES]
            raise ArgumentError, "Ed25519 private key does not include matching public key" unless sk[KEY_BYTES, KEY_BYTES] == pk

            @sign_key = ED25519.new_private_key(private_key_bytes)
            raise ArgumentError, "Ed25519 public key does not match private key" unless @sign_key.raw_public_key == pk

            @public_key_bytes = pk.dup.force_encoding('BINARY')
            @private_key_bytes = private_key_bytes.dup.force_encoding('BINARY')
            @comment = comment
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
