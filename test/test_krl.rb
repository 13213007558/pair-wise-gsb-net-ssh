require "tempfile"
require "tmpdir"

require "common"

class TestKRL < NetSSHTest
  KRL_MAGIC = "SSHKRL\n\0"

  FakeCertificate = Struct.new(:key, :signature_key, :serial, :key_id, keyword_init: true) do
    def to_blob
      key.to_blob
    end
  end

  def setup
    @ca_pem = OpenSSL::PKey::RSA.new(2048).to_pem
    @other_ca_pem = OpenSSL::PKey::RSA.new(2048).to_pem
    @host_pem = OpenSSL::PKey::RSA.new(2048).to_pem
    @ca_key = OpenSSL::PKey::RSA.new(@ca_pem)
    @other_ca_key = OpenSSL::PKey::RSA.new(@other_ca_pem)
    @host_key = OpenSSL::PKey::RSA.new(@host_pem)
    @certificate = build_cert(@ca_key, @host_key, serial: 5, key_id: "host-a")
    @other_certificate = build_cert(@other_ca_key, @host_key, serial: 5, key_id: "host-b")
  end

  def test_revokes_explicit_key_and_returns_reason
    path = write_krl(explicit_section(@host_key.to_blob))
    krl = Net::SSH::KRL.load_file(path)

    revocation = krl.revoked?(@host_key)

    assert_equal :explicit_key, revocation.type
    assert_equal File.expand_path(path), revocation.source
  end

  def test_revokes_sha256_fingerprint
    digest = OpenSSL::Digest.digest('SHA256', @host_key.to_blob)
    path = write_krl(fingerprint_section(5, digest))

    assert_equal :sha256_key_fingerprint,
                 Net::SSH::KRL.load_file(path).revoked?(@host_key).type
  end

  def test_revokes_certificate_serial_scoped_to_ca
    path = write_krl(certificate_section(@ca_key, cert_serial_subsection(5)))
    krl = Net::SSH::KRL.load_file(path)

    assert_equal :certificate_serial, krl.revoked?(@certificate).type
    assert_nil krl.revoked?(@other_certificate)
  end

  def test_multiple_certificate_authority_groups_keep_serial_identity_boundary
    first_group = certificate_group(@ca_key, cert_serial_subsection(5))
    second_group = certificate_group(@other_ca_key, cert_serial_subsection(7))
    path = write_krl(section(1, first_group + second_group))
    krl = Net::SSH::KRL.load_file(path)

    assert_equal :certificate_serial,
                 krl.revoked?(build_cert(@ca_key, @host_key, serial: 5)).type
    assert_nil krl.revoked?(build_cert(@ca_key, @host_key, serial: 7))
    assert_equal :certificate_serial,
                 krl.revoked?(build_cert(@other_ca_key, @host_key, serial: 7)).type
    assert_nil krl.revoked?(build_cert(@other_ca_key, @host_key, serial: 5))
  end

  def test_revokes_certificate_key_id_scoped_to_ca
    same_serial_other_ca = build_cert(@other_ca_key, @host_key, serial: 7, key_id: "host-a")
    path = write_krl(certificate_section(@ca_key, cert_key_id_subsection("host-a")))
    krl = Net::SSH::KRL.load_file(path)

    assert_equal :certificate_key_id, krl.revoked?(@certificate).type
    assert_nil krl.revoked?(same_serial_other_ca)
  end

  def test_serial_range_does_not_expand_to_an_array
    path = write_krl(certificate_section(@ca_key, cert_range_subsection(100, 100 + (1 << 30))))
    krl = Net::SSH::KRL.load_file(path)
    cert = build_cert(@ca_key, @host_key, serial: 100 + (1 << 30))

    revocation = krl.revoked?(cert)
    assert_equal :certificate_serial_range, revocation.type
    assert_equal 100..(100 + (1 << 30)), revocation.detail.minimum..revocation.detail.maximum
  end

  def test_serial_bitmap
    path = write_krl(certificate_section(@ca_key,
                                        cert_bitmap_subsection(5, bits_for(0, 2, 5))))
    krl = Net::SSH::KRL.load_file(path)

    [5, 7, 10].each do |serial|
      cert = build_cert(@ca_key, @host_key, serial: serial)
      assert_equal :certificate_serial_bitmap, krl.revoked?(cert).type
    end

    [4, 6, 8, 9, 11].each do |serial|
      cert = build_cert(@ca_key, @host_key, serial: serial)
      assert_nil krl.revoked?(cert)
    end
  end

  def test_malformed_krl_is_distinct_from_revocation
    path = Tempfile.create(['bad', '.krl']).tap do |file|
      File.binwrite(file, "not a krl")
    end

    assert_raises(Net::SSH::KRLParseError) do
      Net::SSH::KRL.load_file(path)
    end
  end

  def test_unknown_critical_extension_is_rejected_at_load
    extension = Net::SSH::Buffer.from(:string, "custom",
                                     :bool, true,
                                     :string, "data").to_s
    path = write_krl(section(0xFF, extension))

    assert_raises(Net::SSH::KRLParseError) do
      Net::SSH::KRL.load_file(path)
    end
  end

  def test_unknown_critical_certificate_extension_is_rejected_at_load
    subsection = Net::SSH::Buffer.from(:string, "custom",
                                      :bool, true,
                                      :string, "data").to_s
    path = write_krl(certificate_section(@ca_key, cert_extension_subsection(subsection)))

    assert_raises(Net::SSH::KRLParseError) do
      Net::SSH::KRL.load_file(path)
    end
  end

  def test_verifier_rejects_before_known_hosts_and_does_not_remember
    path = write_krl(certificate_section(@ca_key, cert_serial_subsection(5)))
    verifier = Net::SSH::Verifiers::AcceptNew.new
    session = OpenStruct.new(
      host_keys: Net::SSH::HostKeys.new([], OpenStruct.new, {}),
      options: { revoked_host_keys_file: [path] },
      port: 22,
      peer: { ip: "1.2.3.4" }
    )

    error = assert_raises(Net::SSH::HostKeyRevoked) do
      verifier.verify(session: session, key: @certificate, fingerprint: "SHA256:test")
    end
    assert_match(/revoked/, error.message)
    assert_empty session.host_keys
  end

  private

  def build_cert(ca_key, host_key, serial:, key_id: "host")
    FakeCertificate.new(key: host_key, signature_key: ca_key, serial: serial, key_id: key_id)
  end

  def write_krl(*sections)
    file = Tempfile.new(['revoked', '.krl'])
    file.binmode
    file.write(krl_header)
    sections.each { |data| file.write(data) }
    file.flush
    file.path
  ensure
    file&.close
  end

  def krl_header
    KRL_MAGIC.dup.force_encoding('BINARY') +
      [1].pack('N') +
      [0].pack('N') +
      [0].pack('Q>') +
      [0].pack('N') +
      [0].pack('N') +
      [0].pack('N') +
      [0].pack('N') +
      [0].pack('N')
  end

  def section(type, payload)
    [type].pack('C') + [payload.bytesize].pack('N') + payload
  end

  def explicit_section(key_blob)
    section(2, Net::SSH::Buffer.from(:string, key_blob).to_s)
  end

  def fingerprint_section(type, digest)
    section(type, [digest.bytesize].pack('N') + digest)
  end

  def certificate_section(ca_key, *subsections)
    section(1, certificate_group(ca_key, *subsections))
  end

  def certificate_group(ca_key, *subsections)
    Net::SSH::Buffer.from(:string, ca_key.to_blob).to_s + subsections.join
  end

  def cert_subsection(type, payload)
    [0].pack('N') + [type].pack('C') + [payload.bytesize].pack('N') + payload
  end

  def cert_serial_subsection(serial)
    cert_subsection(0x20, [serial].pack('Q>'))
  end

  def cert_range_subsection(minimum, maximum)
    cert_subsection(0x21, [minimum, maximum].pack('Q>Q>'))
  end

  def cert_bitmap_subsection(offset, bits)
    payload = [offset].pack('Q>') + [bits.bytesize].pack('N') + bits
    cert_subsection(0x22, payload)
  end

  def cert_key_id_subsection(key_id)
    cert_subsection(0x23, Net::SSH::Buffer.from(:string, key_id).to_s)
  end

  def cert_extension_subsection(inner)
    cert_subsection(0x39, inner)
  end

  def bits_for(*serials)
    bytes = Array.new(8, 0)
    serials.each do |serial|
      bytes[serial / 8] |= 1 << (serial % 8)
    end
    bytes.pack('C*')
  end
end
