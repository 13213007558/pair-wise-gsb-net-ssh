require 'set'
require 'openssl'
require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/authentication/certificate'

module Net
  module SSH
    # Parses and evaluates OpenSSH Key Revocation Lists (KRLs), as specified
    # in the OpenSSH PROTOCOL.krl document. A KRL is read from a local,
    # trusted file (see the :krl_file option of Net::SSH.start) and consulted
    # by the host-key verifiers before a server key is accepted.
    #
    # Revocation by plain key, by SHA1/SHA256 fingerprint, and -- for
    # certificates signed by a given CA -- by serial number (list, range, or
    # bitmap) and by key ID are supported. Serial ranges and bitmaps are kept
    # in their compact wire form; huge ranges are never expanded into Ruby
    # arrays.
    #
    # A malformed list is reported at load time by raising
    # Net::SSH::KRL::CorruptError, which is deliberately distinct from a key
    # actually being revoked (reported by #revocation returning a Revocation).
    class KRL
      MAGIC = "SSHKRL\n\0".b
      FORMAT_VERSION = 1

      SECTION_CERTIFICATES = 1
      SECTION_EXPLICIT_KEY = 2
      SECTION_FINGERPRINT_SHA1 = 3
      SECTION_SIGNATURE = 4
      SECTION_FINGERPRINT_SHA256 = 5
      SECTION_EXTENSION = 255

      CERT_SERIAL_LIST = 0x20
      CERT_SERIAL_RANGE = 0x21
      CERT_SERIAL_BITMAP = 0x22
      CERT_KEY_ID = 0x23

      # Raised when a KRL cannot be parsed or violates the format, including
      # KRLs carrying unknown critical extensions.
      class CorruptError < Net::SSH::Exception; end

      # Describes why a key matched the revocation list. +reason+ is one of
      # :explicit_key, :fingerprint_sha1, :fingerprint_sha256, :serial_list,
      # :serial_range, :serial_bitmap or :key_id. +ca+ is the wire blob of
      # the CA the match was scoped to (nil for key-wide sections), and
      # +detail+ carries the matched serial number or key ID where
      # applicable.
      Revocation = Struct.new(:reason, :ca, :detail)

      # Sequential reader that raises CorruptError on truncation instead of
      # silently clamping reads the way Net::SSH::Buffer does.
      class Reader # :nodoc:
        def initialize(data)
          @data = data
          @pos = 0
        end

        def eof?
          @pos >= @data.bytesize
        end

        def read(count)
          raise CorruptError, "truncated KRL" if count.negative? || @pos + count > @data.bytesize

          chunk = @data.byteslice(@pos, count)
          @pos += count
          chunk
        end

        def byte
          read(1).getbyte(0)
        end

        def long
          read(4).unpack1("N")
        end

        def int64
          hi = long
          lo = long
          (hi << 32) | lo
        end

        def string
          read(long)
        end

        def buffer
          Reader.new(string)
        end
      end

      attr_reader :version, :generated_date, :flags, :comment

      # Loads and parses the KRL stored in the local file at +path+.
      def self.load_file(path)
        new(File.binread(path))
      end

      def initialize(blob)
        @explicit_keys = Set.new
        @fingerprints = { sha1: Set.new, sha256: Set.new }
        @cert_sections = {}
        parse(Reader.new(blob))
      end

      # Returns true if +key+ (a public key or a
      # Net::SSH::Authentication::Certificate) is revoked by this list.
      def revoked?(key)
        !revocation(key).nil?
      end

      # Returns a Revocation describing why +key+ is revoked, or nil if the
      # key is not on the list. Certificate serial and key ID sections are
      # scoped to the CA that signed the certificate: two certificates with
      # the same serial but different signing CAs are independent identities.
      def revocation(key)
        if key.is_a?(Net::SSH::Authentication::Certificate)
          ca_blob = key.signature_key.to_blob

          reason = serial_revocation(ca_blob, key.serial)
          return Revocation.new(reason, ca_blob, key.serial) if reason

          return Revocation.new(:key_id, ca_blob, key.key_id) if key_id_revoked?(ca_blob, key.key_id)
        end

        blob = Net::SSH::Buffer.from(:key, key).to_s
        return Revocation.new(:explicit_key) if @explicit_keys.include?(blob)

        if @fingerprints[:sha1].include?(OpenSSL::Digest.digest('SHA1', blob))
          return Revocation.new(:fingerprint_sha1)
        end

        if @fingerprints[:sha256].include?(OpenSSL::Digest.digest('SHA256', blob))
          return Revocation.new(:fingerprint_sha256)
        end

        nil
      end

      private

      def parse(reader)
        raise CorruptError, "not a KRL (bad magic)" unless reader.read(MAGIC.bytesize) == MAGIC

        format_version = reader.long
        unless format_version == FORMAT_VERSION
          raise CorruptError, "unsupported KRL format version #{format_version}"
        end

        @version = reader.int64
        @generated_date = reader.int64
        @flags = reader.int64
        @comment = reader.string
        reader.string # reserved

        parse_sections(reader)
      end

      def parse_sections(reader)
        until reader.eof?
          type = reader.byte
          section = reader.buffer
          case type
          when SECTION_CERTIFICATES then parse_certificates(section)
          when SECTION_EXPLICIT_KEY then parse_explicit_keys(section)
          when SECTION_FINGERPRINT_SHA1 then parse_fingerprints(section, :sha1, 20)
          when SECTION_FINGERPRINT_SHA256 then parse_fingerprints(section, :sha256, 32)
          when SECTION_SIGNATURE then nil # KRL signatures are not verified
          when SECTION_EXTENSION then parse_extension(section)
          else raise CorruptError, "unsupported KRL section #{type}"
          end
        end
      end

      def parse_certificates(section)
        # Each certificates section covers a single CA: the CA key blob and
        # a reserved u32, followed by one or more subsections. Multiple CAs
        # appear as multiple certificates sections.
        ca = section.string
        section.long # reserved
        entry = (@cert_sections[ca] ||= new_cert_section)

        until section.eof?
          type = section.byte
          data = section.buffer

          case type
          when CERT_SERIAL_LIST
            require_ca!(ca, "serial list")
            entry[:serials] << data.int64 until data.eof?
          when CERT_SERIAL_RANGE
            require_ca!(ca, "serial range")
            min = data.int64
            max = data.int64
            raise CorruptError, "serial range with max < min" if max < min

            entry[:ranges] << (min..max)
          when CERT_SERIAL_BITMAP
            require_ca!(ca, "serial bitmap")
            entry[:bitmaps] << [data.int64, read_bitmap(data)]
          when CERT_KEY_ID
            entry[:key_ids] << data.string
          else
            raise CorruptError, "unsupported certificate subsection #{type}"
          end

          raise CorruptError, "trailing data in certificate subsection" unless data.eof?
        end
      end

      def parse_explicit_keys(section)
        @explicit_keys << section.string until section.eof?
      end

      def parse_fingerprints(section, hash, digest_length)
        until section.eof?
          digest = section.string
          unless digest.bytesize == digest_length
            raise CorruptError, "bad #{hash} fingerprint length #{digest.bytesize}"
          end

          @fingerprints[hash] << digest
        end
      end

      def parse_extension(section)
        name = section.string
        contents = section.buffer
        critical = contents.long
        return if critical.zero?

        raise CorruptError, "unsupported critical KRL extension #{name.inspect}"
      end

      def new_cert_section
        { serials: Set.new, ranges: [], bitmaps: [], key_ids: Set.new }
      end

      # Serial bitmaps are encoded as SSH bignums: an unsigned big-endian
      # integer whose bit N corresponds to serial (offset + N). Read as an
      # Integer so membership tests are simple bit references, without
      # expanding anything into arrays.
      def read_bitmap(data)
        blob = data.string
        blob.bytes.reduce(0) { |acc, byte| (acc << 8) | byte }
      end

      def require_ca!(ca, what)
        raise CorruptError, "KRL contains #{what} without a CA key" if ca.empty?
      end

      # Looks +serial+ up in the sections scoped to +ca_blob+ without ever
      # expanding ranges or bitmaps into Ruby arrays.
      def serial_revocation(ca_blob, serial)
        entry = @cert_sections[ca_blob]
        return nil unless entry

        return :serial_list if entry[:serials].include?(serial)
        return :serial_range if entry[:ranges].any? { |range| range.cover?(serial) }

        entry[:bitmaps].each do |offset, bitmap|
          index = serial - offset
          next if index.negative?

          return :serial_bitmap if bitmap[index] == 1
        end

        nil
      end

      # Key ID sections exist both scoped to a CA and globally (empty CA
      # blob, matching certificates from any CA).
      def key_id_revoked?(ca_blob, key_id)
        scoped = @cert_sections[ca_blob]
        return true if scoped && scoped[:key_ids].include?(key_id)

        global = @cert_sections[""]
        !!(global && global[:key_ids].include?(key_id))
      end
    end
  end
end
