require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/transport/openssl'
require 'net/ssh/authentication/pub_key_fingerprint'
require 'net/ssh/authentication/ed25519'

module Net
  module SSH
    module Authentication
      module SecurityKey
        ED25519_TYPE = "sk-ssh-ed25519@openssh.com"
        ECDSA_NISTP256_TYPE = "sk-ecdsa-sha2-nistp256@openssh.com"

        USER_PRESENCE_REQUIRED = 1
        USER_VERIFICATION_REQUIRED = 4

        VALID_REQUEST_FLAGS = [
          0,
          USER_PRESENCE_REQUIRED,
          USER_VERIFICATION_REQUIRED,
          USER_PRESENCE_REQUIRED | USER_VERIFICATION_REQUIRED
        ].freeze

        def self.flags(flags = nil)
          flags ||= USER_PRESENCE_REQUIRED
          unless flags.is_a?(Integer) && VALID_REQUEST_FLAGS.include?(flags)
            raise ArgumentError, "unsupported security key flags: #{flags.inspect}"
          end

          flags
        end

        module PubKeyBehavior
          include Net::SSH::Authentication::PubKeyFingerprint

          attr_reader :application

          def ssh_signature_type
            ssh_type
          end

          def security_key?
            true
          end

          def to_pem
            ssh_type + [to_blob].pack("m")
          end

          def ssh_do_verify(sig, data, _options = {})
            return false unless sig.is_a?(String)

            buffer = Net::SSH::Buffer.new(sig)
            flags = buffer.read_byte
            counter = buffer.read_long
            inner_signature = buffer.read_string

            return false unless valid_response_flags?(flags) && counter && inner_signature && buffer.eof?

            signed_data = Net::SSH::Buffer.from(:string, application,
                                                :byte, flags,
                                                :long, counter,
                                                :string, data).to_s
            verify_security_key_signature(inner_signature, signed_data)
          rescue OpenSSL::PKey::PKeyError, ArgumentError
            false
          end

          private

          def valid_response_flags?(flags)
            flags.is_a?(Integer) &&
              (flags & ~(USER_PRESENCE_REQUIRED | USER_VERIFICATION_REQUIRED)).zero?
          end

          def verify_security_key_signature(signature, data)
            raise NotImplementedError, "subclasses must implement verify_security_key_signature"
          end

          def read_application(application)
            raise ArgumentError, "security key application must not be empty" if application.nil? || application.empty?

            application.to_s.dup.force_encoding('BINARY')
          end
        end

        class ED25519PubKey
          include PubKeyBehavior

          def initialize(public_key_bytes, application)
            ED25519.validate_key_bytes!(public_key_bytes, "public key", ED25519::KEY_BYTES)
            @public_key_bytes = public_key_bytes.dup.force_encoding('BINARY')
            @application = read_application(application)
          end

          def self.read_keyblob(buffer)
            public_key_bytes = buffer.read_string
            application = buffer.read_string
            new(public_key_bytes, application)
          end

          def ssh_type
            ED25519_TYPE
          end

          def to_blob
            Net::SSH::Buffer.from(:string, ssh_type,
                                  :string, public_key_bytes,
                                  :string, application).to_s
          end

          def public_key_bytes
            @public_key_bytes.dup
          end

          private

          def verify_security_key_signature(signature, data)
            ED25519.verify(verify_key, signature, data)
          end

          def verify_key
            @verify_key ||= ED25519.new_public_key(@public_key_bytes)
          end
        end

        class ECDSANistp256PubKey
          include PubKeyBehavior

          CURVE_NAME = 'nistp256'

          def initialize(public_key_octet, application)
            begin
              group = OpenSSL::PKey::EC::Group.new(OpenSSL::PKey::EC::CurveNameAlias[CURVE_NAME])
              @point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(public_key_octet, 2))
            rescue OpenSSL::PKey::ECError, ArgumentError
              raise ArgumentError, "invalid security key ECDSA public key"
            end

            @application = read_application(application)
          end

          def self.read_keyblob(buffer)
            curve_name = buffer.read_string
            unless curve_name == CURVE_NAME
              raise Net::SSH::Exception, "curve name mismatched (`#{curve_name}' with `#{CURVE_NAME}')"
            end

            new(buffer.read_string, buffer.read_string)
          end

          def ssh_type
            ECDSA_NISTP256_TYPE
          end

          def to_blob
            Net::SSH::Buffer.from(:string, ssh_type,
                                  :string, CURVE_NAME,
                                  :mstring, @point.to_octet_string(:uncompressed),
                                  :string, application).to_s
          end

          def public_key_bytes
            @point.to_octet_string(:uncompressed)
          end

          private

          def verify_security_key_signature(signature, data)
            buffer = Net::SSH::Buffer.new(signature)
            r = buffer.read_bignum
            s = buffer.read_bignum
            return false unless r && s && buffer.eof?

            asn1_signature = OpenSSL::ASN1::Sequence.new([
              OpenSSL::ASN1::Integer.new(r),
              OpenSSL::ASN1::Integer.new(s)
            ])
            verify_key.dsa_verify_asn1(OpenSSL::Digest::SHA256.digest(data), asn1_signature.to_der)
          end

          def verify_key
            @verify_key ||= OpenSSL::PKey::EC.read_keyblob(CURVE_NAME, Net::SSH::Buffer.from(
              :string, CURVE_NAME,
              :string, @point.to_octet_string(:uncompressed)
            ))
          end
        end
      end
    end
  end
end
