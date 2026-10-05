require 'digest'

require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/key_factory'

module Net
  module SSH
    # Parses and queries OpenSSH Key Revocation Lists.
    class KRL
      MAGIC = "SSHKRL\x00".b.freeze
      VERSION = 1

      CERTIFICATES = 1
      EXPLICIT_KEYS = 2
      FINGERPRINT_SHA1_HASHES = 3
      SIGNATURE = 4
      FINGERPRINT_SHA256_HASHES = 5

      CERT_SERIALS_LIST = 0x20
      CERT_SERIALS_RANGE = 0x21
      CERT_SERIALS_BITMAP = 0x22
      CERT_KEY_IDS = 0x23
      CERT_EXTENSIONS = 0x39
      EXTENSIONS = 0xff
      NON_CRITICAL_BIT = 0x80

      class ParseError < Net::SSH::Exception; end

      class << self
        def load_file(path)
          path = File.expand_path(path)
          data = File.binread(path)
          return RevokedKeysFile.parse(data) unless data.start_with?(MAGIC)

          new(data)
        rescue SystemCallError => e
          raise ParseError, "Unable to load KRL #{path.inspect}: #{e.message}"
        end
      end

      def initialize(blob)
        @explicit_keys = []
        @sha1_hashes = []
        @sha256_hashes = []
        @certificate_sections = []
        parse(blob.to_s.dup.force_encoding("BINARY"))
      rescue ParseError
        raise
      rescue StandardError => e
        raise ParseError, "Invalid KRL: #{e.message}"
      end

      class RevokedKeysFile
        def self.parse(data)
          keys = data.each_line.filter_map do |line|
            next if line.strip.empty? || line.start_with?('#')

            begin
              Net::SSH::KeyFactory.load_data_public_key(line).to_blob
            rescue StandardError => e
              raise ParseError, "Invalid revoked keys file: #{e.message}"
            end
          end
          new(keys)
        end

        def initialize(keys)
          @keys = keys
        end

        def revoked?(key)
          return true if @keys.include?(key.to_blob)

          key.is_a?(Authentication::Certificate) &&
            (@keys.include?(key.key.to_blob) || @keys.include?(key.signature_key.to_blob))
        end
      end

      def revoked?(key)
        blob = key.to_blob
        return true if explicit_key?(blob)
        return true if @sha1_hashes.include?(Digest::SHA1.digest(blob))
        return true if @sha256_hashes.include?(Digest::SHA256.digest(blob))

        certificate?(key)
      end

      private

      def parse(blob)
        buffer = Buffer.new(blob)
        magic = read_bytes!(buffer, MAGIC.bytesize)
        raise ParseError, "bad KRL magic header" unless magic == MAGIC

        version = read_value!(buffer, :read_long)
        raise ParseError, "unsupported KRL format version #{version}" unless version == VERSION

        read_value!(buffer, :read_int64)
        read_string!(buffer)
        parse_sections(buffer)
      end

      def parse_sections(buffer)
        until buffer.eof?
          type = read_value!(buffer, :read_byte)
          section = read_buffer!(buffer)

          case type
          when CERTIFICATES
            parse_certificates(section)
          when EXPLICIT_KEYS
            parse_explicit_keys(section)
          when FINGERPRINT_SHA1_HASHES
            parse_fingerprint_hashes(section, 20, @sha1_hashes)
          when SIGNATURE
            raise ParseError, "Unsupported KRL signature section"
          when FINGERPRINT_SHA256_HASHES
            parse_fingerprint_hashes(section, 32, @sha256_hashes)
          when EXTENSIONS
            parse_extensions(section)
          else
            if (type & NON_CRITICAL_BIT).zero?
              raise ParseError, "Unsupported KRL section #{type}"
            else
              next
            end
          end

          raise ParseError, "KRL section contains unparsed data" unless section.eof?
        end
      end

      def parse_explicit_keys(buffer)
        read_string!(buffer)
        until buffer.eof?
          @explicit_keys << read_buffer!(buffer).read_key.to_blob
        end
      end

      def parse_fingerprint_hashes(buffer, length, destination)
        read_string!(buffer)
        until buffer.eof?
          digest = read_string!(buffer)
          raise ParseError, "bad length" unless digest.bytesize == length

          destination << digest
        end
      end

      def parse_certificates(buffer)
        ca = read_buffer!(buffer).read_key
        section = CertificateSection.new(ca.to_blob)

        until buffer.eof?
          type = read_value!(buffer, :read_byte)
          body = read_buffer!(buffer)

          case type
          when CERT_SERIALS_LIST
            parse_serial_list(section, body)
          when CERT_SERIALS_RANGE
            parse_serial_range(section, body)
          when CERT_SERIALS_BITMAP
            parse_serial_bitmap(section, body)
          when CERT_KEY_IDS
            parse_key_ids(section, body)
          when CERT_EXTENSIONS
            parse_extensions(body)
          else
            if (type & NON_CRITICAL_BIT).zero?
              raise ParseError, "Unsupported KRL certificate section #{type}"
            else
              next
            end
          end

          raise ParseError, "KRL certificate section contains unparsed data" unless body.eof?
        end

        @certificate_sections << section
      end

      def parse_serial_list(section, buffer)
        until buffer.eof?
          serial = read_value!(buffer, :read_int64)
          section.add_serial(serial, serial)
        end
      end

      def parse_serial_range(section, buffer)
        section.add_serial(read_value!(buffer, :read_int64), read_value!(buffer, :read_int64))
      end

      def parse_serial_bitmap(section, buffer)
        first = read_value!(buffer, :read_int64)
        bitmap = read_string!(buffer)
        raise ParseError, "invalid bitmap" unless (bitmap.bytesize % 4).zero?

        bitmap.unpack("V*").each_with_index do |word, word_index|
          32.times do |bit|
            next if word & (1 << bit) == 0

            serial = first + (word_index * 32) + bit
            raise ParseError, "bitmap wraps u64" if serial < first || serial > (1 << 64) - 1

            section.add_serial(serial, serial)
          end
        end
      end

      def parse_key_ids(section, buffer)
        until buffer.eof?
          section.key_ids << read_string!(buffer)
        end
      end

      def parse_extensions(buffer)
        read_string!(buffer)
        until buffer.eof?
          name = read_string!(buffer)
          critical = read_value!(buffer, :read_byte) != 0
          read_string!(buffer)

          raise ParseError, "KRL contains unsupported critical section #{name.inspect}" if critical
        end
      end

      def explicit_key?(blob)
        @explicit_keys.include?(blob)
      end

      def certificate?(key)
        return false unless key.is_a?(Authentication::Certificate)

        ca_blob = key.signature_key.to_blob
        underlying_blob = key.key.to_blob
        return true if explicit_key?(key.to_blob)
        return true if hash_revoked?(ca_blob) || hash_revoked?(underlying_blob)

        @certificate_sections.any? do |section|
          section.ca == ca_blob &&
            (section.serial_revoked?(key.serial) || section.key_ids.include?(key.key_id))
        end
      end

      def hash_revoked?(blob)
        @sha1_hashes.include?(Digest::SHA1.digest(blob)) ||
          @sha256_hashes.include?(Digest::SHA256.digest(blob))
      end

      def read_buffer!(buffer)
        Buffer.new(read_string!(buffer))
      end

      def read_string!(buffer)
        value = buffer.read_string
        raise ParseError, "truncated KRL" if value.nil?

        value
      end

      def read_bytes!(buffer, length)
        value = buffer.read(length)
        raise ParseError, "truncated KRL" if value.nil? || value.bytesize != length

        value
      end

      def read_value!(buffer, method)
        value = buffer.public_send(method)
        raise ParseError, "truncated KRL" if value.nil?

        value
      end

      class CertificateSection
        attr_reader :ca, :serial_ranges, :key_ids

        def initialize(ca)
          @ca = ca
          @serial_ranges = []
          @key_ids = []
        end

        def add_serial(first, last)
          raise ParseError, "invalid serial range #{first}:#{last}" if first <= 0 || last < first

          @serial_ranges << [first, last]
        end

        def serial_revoked?(serial)
          @serial_ranges.any? { |first, last| serial >= first && serial <= last }
        end
      end
      private_constant :CertificateSection
    end
  end
end
