require 'digest'

require 'net/ssh/buffer'
require 'net/ssh/errors'

module Net
  module SSH
    # Parses and queries an OpenSSH Key Revocation List.
    class KRL
      class ParseError < Net::SSH::Exception; end

      MAGIC = "SSHKRL\n\0"
      VERSION = 1
      FORMAT_CRITICAL = 0x01

      SECTION_CRITICAL = 0x80
      SECTION_CERTIFICATE = 0x01
      SECTION_PUBLIC_KEY = 0x02
      SECTION_PUBLIC_KEY_SHA1 = 0x03
      SECTION_PUBLIC_KEY_SHA256 = 0x04
      SECTION_SIGNATURE = 0x05
      SECTION_EXTENSION = 0x06

      CERT_SERIAL_LIST = 0x00
      CERT_SERIAL_RANGE = 0x01
      CERT_SERIAL_BITMAP = 0x02
      CERT_KEY_ID = 0x03

      def self.load_file(path)
        new(File.binread(File.expand_path(path.to_s)))
      end

      def self.read(data)
        new(data)
      end

      def initialize(data)
        @keys = []
        @sha1_hashes = []
        @sha256_hashes = []
        @certificates = {}
        parse(String.new(data, encoding: Encoding::BINARY))
      end

      def revoked?(key)
        if certificate?(key)
          return true if certificate_revoked?(key)

          candidates = [key.key, key.signature_key]
          return candidates.any? { |candidate| public_key_revoked?(candidate) }
        end

        public_key_revoked?(key)
      end

      private

      def parse(data)
        buffer = Buffer.new(data)

        magic = read!(buffer, :read, MAGIC.bytesize, "KRL magic")
        raise_parse_error("invalid KRL magic") unless magic == MAGIC

        version = read_value!(buffer, :read_long, "KRL version")
        raise_parse_error("unsupported KRL version #{version}") unless version == VERSION

        flags = read_value!(buffer, :read_long, "KRL flags")
        unless flags == 0 || flags == FORMAT_CRITICAL
          raise_parse_error("unsupported KRL flags 0x#{flags.to_s(16)}")
        end

        read_value!(buffer, :read_int64, "generation date")
        reserved1 = read_value!(buffer, :read_string, "reserved section")
        reserved2 = read_value!(buffer, :read_string, "reserved section")
        raise_parse_error("non-empty reserved KRL header fields") unless reserved1.empty? && reserved2.empty?

        parse_sections(buffer)
        raise_parse_error("trailing data after KRL sections") unless buffer.eof?
      end

      def parse_sections(buffer)
        until buffer.eof?
          marker = read_value!(buffer, :read_byte, "section type")
          section_type = marker & ~SECTION_CRITICAL
          critical = (marker & SECTION_CRITICAL) != 0
          section = Buffer.new(read_value!(buffer, :read_string, "section body"))

          case section_type
          when SECTION_CERTIFICATE then parse_certificates(section)
          when SECTION_PUBLIC_KEY then parse_public_keys(section)
          when SECTION_PUBLIC_KEY_SHA1 then parse_public_key_hashes(section, 20)
          when SECTION_PUBLIC_KEY_SHA256 then parse_public_key_hashes(section, 32)
          when SECTION_SIGNATURE then raise ParseError, "signed KRL sections are not supported"
          when SECTION_EXTENSION then parse_extension(section, critical)
          else
            raise_parse_error("unknown critical KRL section 0x#{section_type.to_s(16)}") if critical
          end

          raise_parse_error("trailing data in KRL section") unless section.eof?
        end
      end

      def parse_public_keys(buffer)
        until buffer.eof?
          begin
            key = buffer.read_key
          rescue NotImplementedError, ArgumentError, OpenSSL::PKey::PKeyError
            raise ParseError, "invalid KRL public key"
          end
          raise_parse_error("invalid KRL public key") if key.nil?

          # A certificate listed in a global key section is revoked as a plain
          # public key (its underlying key), matching OpenSSH's sshkey_krl
          # handling. Certificates themselves are matched via certificate
          # sections.
          @keys << (certificate?(key) ? key.key.to_blob : key.to_blob)
        end
      end

      def parse_public_key_hashes(buffer, digest_size)
        hashes = digest_size == 20 ? @sha1_hashes : @sha256_hashes
        raise_parse_error("truncated KRL public key hash section") unless buffer.available % digest_size == 0

        until buffer.eof?
          digest = read!(buffer, :read, digest_size, "public key hash")
          hashes << digest
        end
      end

      def parse_extension(buffer, _critical)
        name = read_value!(buffer, :read_string, "extension name")
        data = read_value!(buffer, :read_string, "extension data")
        critical = read_value!(buffer, :read_bool, "extension criticality")

        return if name == "comment" && !critical && data

        raise_parse_error("unknown#{critical ? ' critical' : ''} KRL extension #{name.inspect}") if critical
      end

      def parse_certificates(buffer)
        ca_key = parse_key_blob(read_value!(buffer, :read_string, "certificate CA"))
        raise_parse_error("certificate KRL entry must be qualified by a CA key") unless plain_key?(ca_key)

        entries = @certificates[ca_key.to_blob] ||= { serials: [], ranges: [], bitmaps: [], key_ids: [] }

        until buffer.eof?
          section_type = read_value!(buffer, :read_byte, "certificate section type")
          section = Buffer.new(read_value!(buffer, :read_string, "certificate section body"))

          case section_type
          when CERT_SERIAL_LIST
            parse_serial_list(section, entries)
          when CERT_SERIAL_RANGE
            parse_serial_ranges(section, entries)
          when CERT_SERIAL_BITMAP
            parse_serial_bitmap(section, entries)
          when CERT_KEY_ID
            parse_key_ids(section, entries)
          else
            raise_parse_error("unsupported KRL certificate section #{section_type}")
          end

          raise_parse_error("trailing data in KRL certificate section") unless section.eof?
        end
      end

      def parse_serial_list(buffer, entries)
        until buffer.eof?
          serial = read_value!(buffer, :read_int64, "certificate serial")
          raise_parse_error("certificate serial zero must be revoked by key ID") unless serial > 0

          entries[:serials] << serial
        end
      end

      def parse_serial_ranges(buffer, entries)
        until buffer.eof?
          first = read_value!(buffer, :read_int64, "serial range start")
          last = read_value!(buffer, :read_int64, "serial range end")
          raise_parse_error("invalid KRL serial range") unless first > 0 && first <= last

          entries[:ranges] << [first, last]
        end
      end

      def parse_serial_bitmap(buffer, entries)
        offset = read_value!(buffer, :read_int64, "serial bitmap offset")
        bitmap = read_value!(buffer, :read_string, "serial bitmap")
        raise_parse_error("invalid KRL serial bitmap") unless offset > 0 && !bitmap.empty?

        entries[:bitmaps] << [offset, bitmap]
      end

      def parse_key_ids(buffer, entries)
        until buffer.eof?
          entries[:key_ids] << read_value!(buffer, :read_string, "certificate key ID")
        end
      end

      def parse_key_blob(blob)
        buffer = Buffer.new(blob)
        type = buffer.read_string
        raise_parse_error("invalid KRL public key") if type.nil?

        key = buffer.read_keyblob(type)
        raise_parse_error("trailing data in KRL public key") unless buffer.eof?

        key
      rescue NotImplementedError, ArgumentError, OpenSSL::PKey::PKeyError => e
        raise ParseError, e.message
      end

      def certificate_revoked?(certificate)
        entries = @certificates[certificate.signature_key.to_blob]
        return false unless entries

        entries[:key_ids].include?(certificate.key_id) ||
          entries[:serials].include?(certificate.serial) ||
          entries[:ranges].any? { |first, last| certificate.serial >= first && certificate.serial <= last } ||
          entries[:bitmaps].any? { |offset, bitmap| bitmap_revoked?(bitmap, certificate.serial - offset) }
      end

      def bitmap_revoked?(bitmap, position)
        return false unless position >= 0

        byte_index, position_in_byte = position.divmod(8)
        return false unless byte_index < bitmap.bytesize

        (bitmap.getbyte(byte_index) & (1 << position_in_byte)) != 0
      end

      def public_key_revoked?(key)
        blob = key.to_blob
        @keys.include?(blob) ||
          @sha1_hashes.include?(Digest::SHA1.digest(blob)) ||
          @sha256_hashes.include?(Digest::SHA256.digest(blob))
      end

      def certificate?(key)
        key.is_a?(Net::SSH::Authentication::Certificate)
      end

      def plain_key?(key)
        !certificate?(key)
      end

      def read_value!(buffer, method, description)
        value = buffer.public_send(method)
        raise_parse_error("missing #{description}") if value.nil?

        value
      end

      def read!(buffer, method, length, description)
        value = buffer.public_send(method, length)
        raise_parse_error("missing #{description}") if value.nil? || value.bytesize != length

        value
      end

      def raise_parse_error(message)
        raise ParseError, message
      end
    end
  end
end
