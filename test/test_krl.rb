require 'common'
require 'net/ssh'
require 'net/ssh/krl'
require 'net/ssh/verifiers/always'
require 'net/ssh/authentication/certificate'
require 'ostruct'
require 'tempfile'

class TestKRL < NetSSHTest
  K = Net::SSH::KRL

  def setup
    @ca1 = OpenSSL::PKey::RSA.new(2048)
    @ca2 = OpenSSL::PKey::RSA.new(2048)
    @host_key = OpenSSL::PKey::RSA.new(2048)
    @other_key = OpenSSL::PKey::RSA.new(2048)
  end

  # --- KRL blob builders -------------------------------------------------

  def build_krl(*sections)
    buf = Net::SSH::Buffer.new
    buf.append(K::MAGIC)
    buf.write_long(K::FORMAT_VERSION)
    buf.write_int64(7) # krl version
    buf.write_int64(1_700_000_000) # generated date
    buf.write_int64(0) # flags
    buf.write_string("") # comment
    buf.write_string("") # reserved
    sections.each { |type, data| buf.write_byte(type); buf.write_string(data) }
    K.new(buf.to_s)
  end

  def string_section(*strings)
    strings.inject(Net::SSH::Buffer.new) { |b, s| b.write_string(s) }.to_s
  end

  def cert_section(ca_blob, *subs)
    buf = Net::SSH::Buffer.new
    buf.write_string(ca_blob)
    buf.write_long(0) # reserved
    subs.each do |type, data|
      buf.write_byte(type)
      buf.write_string(data)
    end
    buf.to_s
  end

  def serial_list_sub(*serials)
    Net::SSH::Buffer.from(:int64, serials).to_s
  end

  def serial_range_sub(min, max)
    Net::SSH::Buffer.from(:int64, min, :int64, max).to_s
  end

  def serial_bitmap_sub(offset, *serials)
    value = 0
    serials.each do |serial|
      value |= 1 << (serial - offset)
    end
    # Serial bitmaps are SSH bignums: unsigned big-endian integers.
    hex = value.to_s(16)
    hex = "0#{hex}" if hex.length.odd?
    bitmap = [hex].pack("H*")
    Net::SSH::Buffer.from(:int64, offset, :string, bitmap).to_s
  end

  def key_id_sub(key_id)
    Net::SSH::Buffer.from(:string, key_id).to_s
  end

  def extension_sub(name, critical)
    Net::SSH::Buffer.from(:string, name, :string, Net::SSH::Buffer.from(:long, critical).to_s).to_s
  end

  def build_cert(serial:, key_id:, ca:, key: nil)
    cert = Net::SSH::Authentication::Certificate.new
    cert.key = key || @host_key
    cert.serial = serial
    cert.type = :host
    cert.key_id = key_id
    cert.valid_principals = ["server.example.com"]
    cert.valid_after = Time.now - 3600
    cert.valid_before = Time.now + 3600
    cert.critical_options = {}
    cert.extensions = {}
    cert.reserved = ""
    cert.sign!(ca)
    cert
  end

  # --- plain key and fingerprint revocation ------------------------------

  def test_revocation_by_explicit_key
    krl = build_krl([K::SECTION_EXPLICIT_KEY, string_section(@host_key.to_blob)])

    assert krl.revoked?(@host_key)
    assert_equal :explicit_key, krl.revocation(@host_key).reason
    assert_nil krl.revocation(@other_key)
    refute krl.revoked?(@other_key)
  end

  def test_revocation_by_fingerprint_sha256
    digest = OpenSSL::Digest.digest('SHA256', @host_key.to_blob)
    krl = build_krl([K::SECTION_FINGERPRINT_SHA256, string_section(digest)])

    assert_equal :fingerprint_sha256, krl.revocation(@host_key).reason
    assert_nil krl.revocation(@other_key)
  end

  def test_revocation_by_fingerprint_sha1
    digest = OpenSSL::Digest.digest('SHA1', @host_key.to_blob)
    krl = build_krl([K::SECTION_FINGERPRINT_SHA1, string_section(digest)])

    assert_equal :fingerprint_sha1, krl.revocation(@host_key).reason
    assert_nil krl.revocation(@other_key)
  end

  # --- certificate serial revocation, scoped to the signing CA -----------

  def test_serial_list_revokes_only_matching_ca
    krl = build_krl([K::SECTION_CERTIFICATES,
                     cert_section(@ca1.to_blob, [K::CERT_SERIAL_LIST, serial_list_sub(42, 99)])])

    revoked = krl.revocation(build_cert(serial: 99, key_id: "a", ca: @ca1))
    assert_equal :serial_list, revoked.reason
    assert_equal @ca1.to_blob, revoked.ca
    assert_equal 99, revoked.detail

    # Same serial, different CA: an independent identity, not revoked.
    assert_nil krl.revocation(build_cert(serial: 99, key_id: "a", ca: @ca2))
    # Same CA, serial not on the list.
    assert_nil krl.revocation(build_cert(serial: 100, key_id: "a", ca: @ca1))
  end

  def test_serial_range_matches_without_expanding
    huge_max = (2**64) - 1
    krl = build_krl([K::SECTION_CERTIFICATES,
                     cert_section(@ca1.to_blob, [K::CERT_SERIAL_RANGE, serial_range_sub(0, huge_max)])])

    # The range is kept in its compact wire form, never expanded into an array.
    ranges = krl.instance_variable_get(:@cert_sections)[@ca1.to_blob][:ranges]
    assert_equal [0..huge_max], ranges

    assert_equal :serial_range, krl.revocation(build_cert(serial: huge_max, key_id: "b", ca: @ca1)).reason
    assert_equal :serial_range, krl.revocation(build_cert(serial: 1, key_id: "b", ca: @ca1)).reason
    assert_nil krl.revocation(build_cert(serial: 1, key_id: "b", ca: @ca2))
  end

  def test_serial_range_boundaries
    krl = build_krl([K::SECTION_CERTIFICATES,
                     cert_section(@ca1.to_blob, [K::CERT_SERIAL_RANGE, serial_range_sub(10, 20)])])

    assert_equal :serial_range, krl.revocation(build_cert(serial: 10, key_id: "c", ca: @ca1)).reason
    assert_equal :serial_range, krl.revocation(build_cert(serial: 20, key_id: "c", ca: @ca1)).reason
    assert_nil krl.revocation(build_cert(serial: 9, key_id: "c", ca: @ca1))
    assert_nil krl.revocation(build_cert(serial: 21, key_id: "c", ca: @ca1))
  end

  def test_serial_bitmap
    krl = build_krl([K::SECTION_CERTIFICATES,
                     cert_section(@ca1.to_blob, [K::CERT_SERIAL_BITMAP, serial_bitmap_sub(1000, 1000, 1005, 1016)])])

    assert_equal :serial_bitmap, krl.revocation(build_cert(serial: 1000, key_id: "d", ca: @ca1)).reason
    assert_equal :serial_bitmap, krl.revocation(build_cert(serial: 1005, key_id: "d", ca: @ca1)).reason
    assert_equal :serial_bitmap, krl.revocation(build_cert(serial: 1016, key_id: "d", ca: @ca1)).reason
    assert_nil krl.revocation(build_cert(serial: 1006, key_id: "d", ca: @ca1))
    assert_nil krl.revocation(build_cert(serial: 999, key_id: "d", ca: @ca1))
    assert_nil krl.revocation(build_cert(serial: 10_000, key_id: "d", ca: @ca1))
    assert_nil krl.revocation(build_cert(serial: 1005, key_id: "d", ca: @ca2))
  end

  # --- key ID revocation ---------------------------------------------------

  def test_key_id_scoped_to_ca
    krl = build_krl([K::SECTION_CERTIFICATES,
                     cert_section(@ca1.to_blob, [K::CERT_KEY_ID, key_id_sub("bad-cert")])])

    revoked = krl.revocation(build_cert(serial: 1, key_id: "bad-cert", ca: @ca1))
    assert_equal :key_id, revoked.reason
    assert_equal "bad-cert", revoked.detail

    # Same key ID under a different CA is a different identity.
    assert_nil krl.revocation(build_cert(serial: 1, key_id: "bad-cert", ca: @ca2))
    assert_nil krl.revocation(build_cert(serial: 1, key_id: "good-cert", ca: @ca1))
  end

  def test_key_id_global_section_matches_any_ca
    krl = build_krl([K::SECTION_CERTIFICATES,
                     cert_section("", [K::CERT_KEY_ID, key_id_sub("bad-cert")])])

    assert_equal :key_id, krl.revocation(build_cert(serial: 1, key_id: "bad-cert", ca: @ca1)).reason
    assert_equal :key_id, krl.revocation(build_cert(serial: 1, key_id: "bad-cert", ca: @ca2)).reason
    assert_nil krl.revocation(build_cert(serial: 1, key_id: "good-cert", ca: @ca1))
  end

  # --- extensions and corruption -------------------------------------------

  def test_unknown_critical_extension_rejects_load
    assert_raises(K::CorruptError) do
      build_krl([K::SECTION_EXTENSION, extension_sub("vendor-x@example.com", 1)])
    end
  end

  def test_noncritical_extension_is_ignored
    krl = build_krl([K::SECTION_EXTENSION, extension_sub("vendor-x@example.com", 0)])
    assert_nil krl.revocation(@host_key)
  end

  def test_corrupt_lists_raise_corrupt_error
    good = build_krl([K::SECTION_EXPLICIT_KEY, string_section(@host_key.to_blob)])

    corrupt = []
    corrupt << "not-a-krl"                                  # bad magic
    corrupt << build_blob { |b| b.write_byte(99) }          # unknown section type
    corrupt << build_blob do |b|                            # truncated section data
      b.write_byte(K::SECTION_EXPLICIT_KEY)
      b.write_string("\x00\x00\x01\x00") # declares 256 bytes, provides 4
    end
    corrupt << build_blob do |b|                            # serial list without CA
      b.write_byte(K::SECTION_CERTIFICATES)
      b.write_string(cert_section("", [K::CERT_SERIAL_LIST, serial_list_sub(1)]))
    end
    corrupt << build_blob do |b|                            # bad digest length
      b.write_byte(K::SECTION_FINGERPRINT_SHA256)
      b.write_string(string_section("too-short"))
    end
    corrupt << build_blob do |b|                            # range with max < min
      b.write_byte(K::SECTION_CERTIFICATES)
      b.write_string(cert_section(@ca1.to_blob, [K::CERT_SERIAL_RANGE, serial_range_sub(20, 10)]))
    end

    corrupt.each do |blob|
      assert_raises(K::CorruptError) { K.new(blob) }
    end

    # A corrupt list raises; it is never confused with a revoked key.
    assert_kind_of Net::SSH::Exception, K::CorruptError.new
    assert_nil good.revocation(@other_key)
  end

  def build_blob
    buf = Net::SSH::Buffer.new
    buf.append(K::MAGIC)
    buf.write_long(K::FORMAT_VERSION)
    buf.write_int64(1)
    buf.write_int64(0)
    buf.write_int64(0)
    buf.write_string("")
    buf.write_string("")
    yield buf
    buf.to_s
  end

  # --- verifier integration --------------------------------------------------

  def with_krl_file(krl_blob)
    Tempfile.create("revoked.krl") do |file|
      file.write(krl_blob)
      file.flush
      yield file.path
    end
  end

  def verifier_session(key, krl_file)
    entry = Net::SSH::HostKeyEntries::PubKey.new(key)
    host_keys = Net::SSH::HostKeys.new([entry], "server.example.com", Net::SSH::KnownHosts, {})
    OpenStruct.new(host_keys: host_keys, port: 22, peer: { ip: "1.2.3.4" },
                   options: { krl_file: krl_file })
  end

  def test_verifier_rejects_revoked_host_key
    blob = build_blob do |b|
      b.write_byte(K::SECTION_EXPLICIT_KEY)
      b.write_string(string_section(@host_key.to_blob))
    end

    with_krl_file(blob) do |path|
      verifier = Net::SSH::Verifiers::Always.new
      error = assert_raises(Net::SSH::HostKeyMismatch) do
        verifier.verify(session: verifier_session(@host_key, path),
                        key: @host_key, fingerprint: "SHA256:test")
      end
      assert_match(/revoked.*explicit_key/, error.message)
    end
  end

  def test_verifier_accepts_key_absent_from_krl
    blob = build_blob do |b|
      b.write_byte(K::SECTION_EXPLICIT_KEY)
      b.write_string(string_section(@other_key.to_blob))
    end

    with_krl_file(blob) do |path|
      verifier = Net::SSH::Verifiers::Always.new
      assert verifier.verify(session: verifier_session(@host_key, path),
                             key: @host_key, fingerprint: "SHA256:test")
    end
  end

  def test_verifier_propagates_corrupt_krl
    with_krl_file("not-a-krl") do |path|
      verifier = Net::SSH::Verifiers::Always.new
      assert_raises(K::CorruptError) do
        verifier.verify(session: verifier_session(@host_key, path),
                        key: @host_key, fingerprint: "SHA256:test")
      end
    end
  end

  def test_verifier_rejects_cert_revoked_by_serial
    cert = build_cert(serial: 99, key_id: "e", ca: @ca1)
    blob = build_blob do |b|
      b.write_byte(K::SECTION_CERTIFICATES)
      b.write_string(cert_section(@ca1.to_blob, [K::CERT_SERIAL_LIST, serial_list_sub(99)]))
    end

    with_krl_file(blob) do |path|
      verifier = Net::SSH::Verifiers::Always.new
      session = verifier_session(cert, path)
      assert_raises(Net::SSH::HostKeyMismatch) do
        verifier.verify(session: session, key: cert, fingerprint: "SHA256:test")
      end

      # The same serial signed by a different CA passes the KRL check (and
      # then fails the known-hosts lookup with an ordinary mismatch, proving
      # the KRL did not reject it).
      other = build_cert(serial: 99, key_id: "e", ca: @ca2)
      error = assert_raises(Net::SSH::HostKeyMismatch) do
        verifier.verify(session: verifier_session(@other_key, path), key: other, fingerprint: "SHA256:test")
      end
      assert_match(/does not match/, error.message)
    end
  end
end
