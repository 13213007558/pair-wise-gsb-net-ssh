require 'openssl'

require 'net/ssh/errors'
require 'net/ssh/authentication/pub_key_fingerprint'
require 'net/ssh/authentication/ed25519_loader'

module Net
  module SSH
    module Authentication
      # Support for the OpenSSH security key (FIDO/U2F) public key types
      # sk-ssh-ed25519@openssh.com and sk-ecdsa-sha2-nistp256@openssh.com,
      # as described in OpenSSH's PROTOCOL.u2f.
      #
      # The private key never leaves the hardware token; signing happens
      # through an ssh-agent (see Net::SSH::Authentication::Agent). This
      # module only deals with public keys and with parsing and verifying
      # the signatures the token produces.
      #
      # A security key signature is not a plain Ed25519/ECDSA signature:
      # the token signs the key's application string, the user
      # presence/verification flags and its signature counter together with
      # the message. Verification therefore needs the whole signature blob
      # (raw signature, flags and counter) and the key's application
      # string; stripping the security key framing and verifying the raw
      # signature against the bare message will (correctly) fail.
      module SecurityKey
        ALGORITHM_ED25519 = "sk-ssh-ed25519@openssh.com"
        ALGORITHM_ECDSA = "sk-ecdsa-sha2-nistp256@openssh.com"
        ALGORITHMS = [ALGORITHM_ED25519, ALGORITHM_ECDSA].freeze

        # Flag bits in a security key signature, as defined by FIDO2.
        USER_PRESENT_FLAG = 0x01
        USER_VERIFIED_FLAG = 0x04

        # The application string OpenSSH uses for SSH signatures.
        DEFAULT_APPLICATION = "ssh:"

        # Raised when a security key signature blob cannot be parsed.
        class InvalidSignatureError < Net::SSH::Exception; end

        # Returns true if the given signature/key algorithm name is one of
        # the OpenSSH security key algorithms.
        def self.algorithm?(name)
          ALGORITHMS.include?(name)
        end

        # An explicit policy describing which authenticator flags a
        # security key signature must (or must not) carry. Each of
        # +user_presence+ and +user_verification+ is one of:
        #
        # * +:required+  - the flag must be set for verification to pass
        # * +:optional+  - the flag may or may not be set
        # * +:forbidden+ - the flag must not be set
        #
        # The default policy requires the user-presence flag (matching
        # OpenSSH, which refuses signatures without it) and treats
        # user-verification as optional.
        class FlagPolicy
          VALUES = %i[required optional forbidden].freeze

          attr_reader :user_presence, :user_verification

          def initialize(user_presence: :required, user_verification: :optional)
            @user_presence = validate(:user_presence, user_presence)
            @user_verification = validate(:user_verification, user_verification)
          end

          # Returns true if the given authenticator flag byte satisfies
          # this policy.
          def allows?(flags)
            requirement_met?((flags & USER_PRESENT_FLAG) != 0, user_presence) &&
              requirement_met?((flags & USER_VERIFIED_FLAG) != 0, user_verification)
          end

          private

          def validate(name, value)
            value = value.to_sym
            return value if VALUES.include?(value)

            raise ArgumentError, "invalid #{name} requirement #{value.inspect} (expected one of #{VALUES.map(&:inspect).join(', ')})"
          end

          def requirement_met?(flag_set, requirement)
            case requirement
            when :required then flag_set
            when :forbidden then !flag_set
            else true
            end
          end
        end

        DEFAULT_FLAG_POLICY = FlagPolicy.new.freeze

        # A parsed security key signature: the raw (Ed25519 or ECDSA)
        # signature plus the authenticator flags and signature counter
        # reported by the token.
        class Signature
          attr_reader :algorithm, :raw_signature, :flags, :counter

          def initialize(raw_signature, flags, counter, algorithm = nil)
            @raw_signature = raw_signature
            @flags = flags
            @counter = counter
            @algorithm = algorithm
          end

          # Parses a security key signature blob as it appears on the wire
          # after the signature algorithm name:
          #
          #   string  raw_signature
          #   byte    flags
          #   uint32  counter
          #
          # Raises InvalidSignatureError if the blob is malformed.
          def self.parse(blob, algorithm: nil)
            buffer = blob.is_a?(Net::SSH::Buffer) ? blob : Net::SSH::Buffer.new(blob)
            raw_signature = buffer.read_string
            flags = buffer.read_byte
            counter = buffer.read_long
            unless raw_signature && flags && counter && buffer.eof?
              raise InvalidSignatureError, "malformed security key signature blob"
            end

            new(raw_signature, flags, counter, algorithm)
          end

          # Reads a full security key signature blob (including the leading
          # algorithm name string, as returned by ssh-agent) from the given
          # buffer. Raises InvalidSignatureError if the algorithm is not a
          # security key algorithm or the blob is malformed.
          def self.read(buffer)
            algorithm = buffer.read_string
            unless SecurityKey.algorithm?(algorithm)
              raise InvalidSignatureError, "not a security key signature algorithm #{algorithm.inspect}"
            end

            parse(buffer.remainder_as_buffer, algorithm: algorithm)
          end

          # Serializes the signature back to its wire format, including the
          # leading algorithm name string.
          def to_blob(algorithm = @algorithm)
            raise ArgumentError, "no signature algorithm known for this signature" if algorithm.nil?

            Net::SSH::Buffer.from(:mstring, algorithm.dup, :string, raw_signature,
                                  :byte, flags, :long, counter).to_s
          end

          def user_present?
            (flags & USER_PRESENT_FLAG) != 0
          end

          def user_verified?
            (flags & USER_VERIFIED_FLAG) != 0
          end

          # The data the security key actually signed for the given
          # application string and message:
          #
          #   string  application
          #   byte    flags
          #   uint32  counter
          #   byte[]  message
          def signed_data(application, message)
            Net::SSH::Buffer.from(:string, application.to_s, :byte, flags,
                                  :long, counter, :raw, message.to_s).to_s
          end
        end

        # Shared behavior of the security key public key types.
        class PubKey
          include Net::SSH::Authentication::PubKeyFingerprint

          # The application string the key was enrolled with ("ssh:" for
          # keys used with the SSH protocol).
          attr_reader :application

          def initialize(application = nil)
            @application = application.nil? || application.empty? ? DEFAULT_APPLICATION.dup : application.dup
          end

          def security_key?
            true
          end

          def ssh_signature_type
            ssh_type
          end

          # Verifies a security key signature. +sig+ is the signature blob
          # as it appears on the wire after the algorithm name (raw
          # signature, flags and counter - see Signature.parse), +data+ is
          # the signed message.
          #
          # The authenticator flags are checked against an explicit policy
          # before the cryptographic verification; pass
          # <tt>options[:flag_policy]</tt> (a FlagPolicy) or the
          # <tt>:user_presence</tt> / <tt>:user_verification</tt>
          # requirements to override the default policy
          # (user-presence required, user-verification optional).
          def ssh_do_verify(sig, data, options = {})
            signature =
              begin
                Signature.parse(sig)
              rescue InvalidSignatureError
                return false
              end
            return false unless flag_policy(options).allows?(signature.flags)

            verify_raw(signature.raw_signature, signature.signed_data(application, data))
          end

          def to_pem
            "#{ssh_type} #{[to_blob].pack('m0')}"
          end

          private

          def flag_policy(options)
            policy = options[:flag_policy]
            return policy if policy

            if options.key?(:user_presence) || options.key?(:user_verification)
              FlagPolicy.new(
                user_presence: options.fetch(:user_presence, :required),
                user_verification: options.fetch(:user_verification, :optional)
              )
            else
              DEFAULT_FLAG_POLICY
            end
          end
        end

        # A sk-ssh-ed25519@openssh.com public key.
        class ED25519PubKey < PubKey
          def initialize(public_key_bytes, application = nil)
            super(application)
            ed25519 = Net::SSH::Authentication::ED25519
            ed25519.validate_key_bytes!(public_key_bytes, "public key", ed25519::KEY_BYTES)
            @public_key_bytes = public_key_bytes.dup.force_encoding('BINARY')
          end

          def self.read_keyblob(buffer)
            new(buffer.read_string, buffer.read_string)
          end

          def ssh_type
            ALGORITHM_ED25519
          end

          def to_blob
            Net::SSH::Buffer.from(:mstring, ssh_type.dup, :string, public_key_bytes,
                                  :string, application).to_s
          end

          def public_key_bytes
            @public_key_bytes.dup
          end

          private

          def verify_raw(raw_signature, signed_data)
            ed25519 = Net::SSH::Authentication::ED25519
            ed25519.verify(verify_key, raw_signature, signed_data)
          rescue OpenSSL::PKey::PKeyError
            false
          end

          def verify_key
            @verify_key ||= Net::SSH::Authentication::ED25519.new_public_key(@public_key_bytes)
          end
        end

        # A sk-ecdsa-sha2-nistp256@openssh.com public key.
        class ECDSAPubKey < PubKey
          CURVE_NAME = "nistp256"

          attr_reader :public_key

          def initialize(public_key, application = nil)
            super(application)
            @public_key = public_key
          end

          def self.read_keyblob(buffer)
            public_key = OpenSSL::PKey::EC.read_keyblob(CURVE_NAME, buffer)
            new(public_key, buffer.read_string)
          end

          def ssh_type
            ALGORITHM_ECDSA
          end

          def to_blob
            Net::SSH::Buffer.from(:mstring, ssh_type.dup, :string, CURVE_NAME.dup,
                                  :mstring, public_key_octets, :string, application).to_s
          end

          def public_key_octets
            public_key.public_key.to_bn.to_s(2)
          end

          private

          def verify_raw(raw_signature, signed_data)
            # OpenSSL::PKey::EC#ssh_do_verify parses the SSH-encoded
            # (r, s) pair and verifies it against SHA256(signed_data),
            # which is exactly the sk-ecdsa-sha2-nistp256 construction.
            public_key.ssh_do_verify(raw_signature, signed_data)
          rescue OpenSSL::PKey::PKeyError
            false
          end
        end
      end
    end
  end
end
