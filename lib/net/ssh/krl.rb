require 'openssl'

require 'net/ssh/buffer'
require 'net/ssh/errors'

module Net
  module SSH
    class KRLParseError < Net::SSH::Exception; end

    # Reads OpenSSH key revocation lists (KRLs) from a local trusted file.
    class KRL
      MAGIC = "SSHKRL\n\0"
      VERSION = 1

      REVOKED_CERTIFICATES = 1
      EXPLICIT_KEYS = 2
      SHA1_KEYS = 3
      SIGNATURE = 4
      SHA256_KEYS = 5
      EXTENSIONS = 0xFF

      CERT_SERIALS = 0x20
      CERT_SERIAL_RANGES = 0x21
      CERT_SERIAL_BITMAP = 0x22
      CERT_KEY_IDS = 0x23
      CERT_EXTENSIONS = 0x39

      Revocation = Struct.new(:type, :detail, :source, keyword_init: true) do
        def to_s
          case type
          when :explicit_key then "explicit key"
          when :sha1_key_fingerprint then "SHA1 key fingerprint"
          when :sha256_key_fingerprint then "SHA256 key fingerprint"
          when :certificate_serial then "certificate serial #{detail}"
          when :certificate_serial_range then "certificate serial range #{detail}"
          when :certificate_serial_bitmap then "certificate serial bitmap at #{detail}"
          when :certificate_key_id then "certificate key ID #{detail.inspect}"
          else type.to_s
          end
        end
      end

      SerialRange = Struct.new(:minimum, :maximum, keyword_init: true) do
        def include?(serial)
          serial >= minimum && serial <= maximum
        end

        def to_s
          minimum == maximum ? minimum.to_s : "#{minimum}-#{maximum}"
        end
      end

      SerialBitmap = Struct.new(:offset, :bits, keyword_init: true) do
        def include?(serial)
          return false if serial < offset
          index = serial - offset
          return false if index >= bits.bytesize * 8

          (bits.getbyte(index / 8) >> (index % 8)) & 1 == 1
        end

        def cover?
          offset + bits.bytesize * 8 - 1 <= 0xFFFFFFFFFFFFFFFF
        end

        def to_s
          "serial #{offset}"
        end
      end

      class CertificateRules
        attr_reader :key_ids

        def initialize(ca_key)
          @ca_key = ca_key
          @serials = []
          @ranges = []
          @bitmaps = []
          @key_ids = []
        end

        def add_serial(serial)
          @serials << serial
        end

        def add_range(minimum, maximum)
          if minimum > maximum || minimum > 0xFFFFFFFFFFFFFFFF || maximum > 0xFFFFFFFFFFFFFFFF
            raise KRLParseError, "invalid certificate serial range #{minimum}-#{maximum}"
          end

          @ranges << SerialRange.new(minimum: minimum, maximum: maximum)
        end

        def add_bitmap(offset, bits)
          bitmap = SerialBitmap.new(offset: offset, bits: bits)
          raise KRLParseError, "certificate serial bitmap wraps beyond 64-bit serial space" unless bitmap.cover?

          @bitmaps << bitmap
        end

        def ca?(certificate)
          certificate.respond_to?(:signature_key) &&
            certificate.signature_key.ssh_type == @ca_key.ssh_type &&
            certificate.signature_key.to_blob == @ca_key.to_blob
        end

        def match(certificate)
          return unless certificate.respond_to?(:serial)

          serial = certificate.serial
          if @serials.include?(serial)
            return Revocation.new(type: :certificate_serial, detail: serial)
          end

          range = @ranges.find { |candidate| candidate.include?(serial) }
          return Revocation.new(type: :certificate_serial_range, detail: range) if range

          bitmap = @bitmaps.find { |candidate| candidate.include?(serial) }
          if bitmap
            return Revocation.new(type: :certificate_serial_bitmap,
                                 detail: [bitmap.offset, serial - bitmap.offset])
          end

          return unless certificate.respond_to?(:key_id) && @key_ids.include?(certificate.key_id)

          Revocation.new(type: :certificate_key_id, detail: certificate.key_id)
        end
      end

      class << self
        def load_file(source)
          source = File.expand_path(source)
          return nil unless File.readable?(source)

          new(File.binread(source), source: source)
        end

        def load_files(sources)
          Array(sources).filter_map { |source| load_file(source) }
        end

        def revoked?(sources, key)
          load_files(sources).each do |krl|
            revocation = krl.revoked?(key)
            return revocation if revocation
          end
          nil
        end
      end

      attr_reader :source

      def initialize(blob, source: nil)
        @source = source
        @explicit_keys = []
        @sha1_fingerprints = []
        @sha256_fingerprints = []
        @certificate_rules = []
        parse(blob.to_s.dup.force_encoding('BINARY'))
      end

      def revoked?(key)
        blob = key_blob(key)
        return unless blob

        underlying_blob = if key.respond_to?(:key) && key.key.respond_to?(:to_blob)
                            key.key.to_blob
                          end
        match = certificate_match(key) ||
                explicit_match(blob) ||
                fingerprint_match(blob) ||
                (underlying_blob && fingerprint_match(underlying_blob))
        return unless match

        match.source = source
        match
      end

      private

      def parse(blob)
        buffer = Buffer.new(blob)
        magic = buffer.read(MAGIC.bytesize)
        raise KRLParseError, "bad KRL magic header" unless magic == MAGIC

        version = buffer.read_long
        raise KRLParseError, "unsupported KRL format version #{version}" unless version == VERSION

        skip!(buffer, 4) # flags
        skip!(buffer, 8) # timestamp
        skip!(buffer, 4) # comment length
        skip!(buffer, 16) # reserved

        parse_sections(buffer)
      end

      def parse_sections(buffer)
        until buffer.eof?
          type = buffer.read_byte
          section = read_section(buffer)

          case type
          when EXPLICIT_KEYS then parse_key_section(section, @explicit_keys)
          when SHA1_KEYS then parse_fingerprint_section(section, @sha1_fingerprints, OpenSSL::Digest::SHA1)
          when SHA256_KEYS then parse_fingerprint_section(section, @sha256_fingerprints, OpenSSL::Digest::SHA256)
          when REVOKED_CERTIFICATES then parse_certificate_section(section)
          when SIGNATURE then nil
          when EXTENSIONS then parse_extensions(section)
          else
            raise KRLParseError, "unsupported KRL section #{type}"
          end

          raise KRLParseError, "KRL section contains unparsed data" unless section.eof?
        end
      end

      def read_section(buffer)
        length = buffer.read_long
        raise KRLParseError, "invalid KRL section length" unless length

        data = buffer.read(length)
        raise KRLParseError, "KRL section is truncated" if data.nil? || data.bytesize != length

        Buffer.new(data)
      end

      def parse_key_section(section, keys)
        until section.eof?
          blob = section.read_string
          raise KRLParseError, "truncated explicit key entry" if blob.nil?

          keys << blob
        end
      end

      def parse_fingerprint_section(section, fingerprints, digest_class)
        until section.eof?
          length = section.read_long
          digest = section.read(length)
          if digest.nil? || digest.bytesize != length
            raise KRLParseError, "truncated fingerprint entry"
          end

          raise KRLParseError, "invalid fingerprint length" unless digest.bytesize == digest_class.new.digest_length

          fingerprints << digest
        end
      end

      def parse_certificate_section(section)
        until section.eof?
          ca_blob = section.read_string
          raise KRLParseError, "truncated certificate CA key" if ca_blob.nil?

          ca_key = Buffer.new(ca_blob).read_key
          rules = CertificateRules.new(ca_key)

          until section.eof?
            marker = section.read_long
            type = if marker.zero?
                     section.read_byte
                   elsif marker <= 0xFF
                     marker
                  elsif marker >= 128 && marker <= section.available
                     section.position -= 4
                     break
                   else
                     raise KRLParseError, "invalid KRL certificate subsection header"
                   end
            length = section.read_long
            data = section.read(length)
            if data.nil? || data.bytesize != length
              raise KRLParseError, "KRL certificate section is truncated"
            end

            payload = Buffer.new(data)
            case type
            when CERT_SERIALS then parse_cert_serial_list(payload, rules)
            when CERT_SERIAL_RANGES then parse_cert_serial_ranges(payload, rules)
            when CERT_SERIAL_BITMAP then parse_cert_serial_bitmap(payload, rules)
            when CERT_KEY_IDS then parse_cert_key_ids(payload, rules)
            when CERT_EXTENSIONS then parse_certificate_extensions(payload)
            else
              raise KRLParseError, "unsupported KRL certificate section #{type}"
            end

            unless payload.eof?
              raise KRLParseError, "KRL certificate section contains unparsed data"
            end

          end

          @certificate_rules << rules
        end

        raise KRLParseError, "KRL certificate section contains unparsed data" unless section.eof?
      end

      def parse_cert_serial_list(payload, rules)
        until payload.eof?
          serial = read_uint64(payload)
          raise KRLParseError, "truncated certificate serial" if serial.nil?

          rules.add_serial(serial)
        end
      end

      def parse_cert_serial_ranges(payload, rules)
        until payload.eof?
          minimum = read_uint64(payload)
          maximum = read_uint64(payload)
          if minimum.nil? || maximum.nil?
            raise KRLParseError, "truncated certificate serial range"
          end

          rules.add_range(minimum, maximum)
        end
      end

      def parse_cert_serial_bitmap(payload, rules)
        offset = read_uint64(payload)
        length = payload.read_long
        bits = payload.read(length) if length
        if offset.nil? || length.nil? || bits.nil? || bits.bytesize != length
          raise KRLParseError, "truncated certificate serial bitmap"
        end

        rules.add_bitmap(offset, bits)
      end

      def read_uint64(buffer)
        high = buffer.read_long
        low = buffer.read_long
        return if high.nil? || low.nil?

        (high << 32) + low
      end

      def parse_cert_key_ids(payload, rules)
        until payload.eof?
          key_id = payload.read_string
          raise KRLParseError, "truncated certificate key ID" if key_id.nil?

          rules.key_ids << key_id
        end
      end

      def parse_extensions(section)
        until section.eof?
          name = section.read_string
          critical = section.read_bool
          data = section.read_string
          if name.nil? || critical.nil? || data.nil?
            raise KRLParseError, "KRL has invalid extension section"
          end

          next unless critical

          raise KRLParseError, "KRL contains unsupported critical section #{name.inspect}"
        end
      end

      def parse_certificate_extensions(section)
        until section.eof?
          name = section.read_string
          critical = section.read_bool
          data = section.read_string
          if name.nil? || critical.nil? || data.nil?
            raise KRLParseError, "KRL has invalid certificate extension subsection"
          end

          next unless critical

          raise KRLParseError,
                "KRL contains unsupported critical certificate subsection #{name.inspect}"
        end
      end

      def explicit_match(blob)
        return unless @explicit_keys.include?(blob)

        Revocation.new(type: :explicit_key, detail: nil)
      end

      def fingerprint_match(blob)
        sha1 = OpenSSL::Digest.digest('SHA1', blob)
        return Revocation.new(type: :sha1_key_fingerprint, detail: sha1) if @sha1_fingerprints.include?(sha1)

        sha256 = OpenSSL::Digest.digest('SHA256', blob)
        return Revocation.new(type: :sha256_key_fingerprint, detail: sha256) if @sha256_fingerprints.include?(sha256)
      end

      def certificate_match(key)
        return unless key.respond_to?(:signature_key)

        @certificate_rules.each do |rules|
          next unless rules.ca?(key)

          revocation = rules.match(key)
          return revocation if revocation
        end
        nil
      end

      def key_blob(key)
        key.to_blob if key.respond_to?(:to_blob)
      end

      def skip!(buffer, length)
        data = buffer.read(length)
        raise KRLParseError, "KRL header is truncated" if data.nil? || data.bytesize != length
      end
    end

  end
end
