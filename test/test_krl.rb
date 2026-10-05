require_relative 'common'

require 'tmpdir'

require 'net/ssh'
require 'net/ssh/krl'
require 'net/ssh/authentication/certificate'
require 'net/ssh/verifiers/accept_new_or_local_tunnel'
require 'net/ssh/verifiers/never'

class TestKRL < NetSSHTest
  TARGET = "host.example.com"

  def setup
    @ca_one = OpenSSL::PKey::EC.generate("prime256v1")
    @ca_two = OpenSSL::PKey::EC.generate("prime256v1")
    @ca_three = OpenSSL::PKey::EC.generate("prime256v1")
    @host_one = OpenSSL::PKey::EC.generate("prime256v1")
    @host_two = OpenSSL::PKey::EC.generate("prime256v1")
  end

  def test_matches_explicit_public_key_and_sha1_and_sha256_fingerprints
    key = Net::SSH::Buffer.new(@host_one.to_blob).read_key
    with_krl_file(
      explicit_section(@host_one.to_blob),
      digest_section(Net::SSH::KRL::FINGERPRINT_SHA1_HASHES, 20, Digest::SHA1.digest(@host_two.to_blob)),
      digest_section(Net::SSH::KRL::FINGERPRINT_SHA256_HASHES, 32, Digest::SHA256.digest(key.to_blob))
    ) do |krl|
      assert Net::SSH::KRL.load_file(krl).revoked?(key)
      assert Net::SSH::KRL.load_file(krl).revoked?(@host_two)
      refute Net::SSH::KRL.load_file(krl).revoked?(@ca_one)
    end
  end

  def test_matches_certificate_key_id_serial_list_range_and_bitmap_with_ca_qualifier
    list_cert = certificate(@ca_one, @host_one, 10, "list-id")
    range_cert = certificate(@ca_one, @host_one, 20, "range-id")
    bitmap_cert = certificate(@ca_one, @host_one, 33, "bitmap-id")
    id_cert = certificate(@ca_one, @host_two, 99, "revoked-id")

    other_ca_range_cert = certificate(@ca_two, @host_one, 20, "other-range-id")
    other_ca_bitmap_cert = certificate(@ca_two, @host_one, 33, "other-bitmap-id")
    other_ca_id_cert = certificate(@ca_two, @host_two, 99, "revoked-id")

    with_krl_file(
      certificate_section(@ca_one,
                          serial_list_subsection(10),
                          range_subsection(19, 21),
                          bitmap_subsection(32, [1 << (33 - 32)].pack("V")),
                          key_id_subsection("revoked-id")),
      certificate_section(@ca_two,
                          serial_list_subsection(11))
    ) do |krl|
      revocation = Net::SSH::KRL.load_file(krl)

      assert revocation.revoked?(list_cert)
      assert revocation.revoked?(range_cert)
      assert revocation.revoked?(bitmap_cert)
      assert revocation.revoked?(id_cert)

      refute revocation.revoked?(other_ca_range_cert)
      refute revocation.revoked?(other_ca_bitmap_cert)
      refute revocation.revoked?(other_ca_id_cert)
    end
  end

  def test_revoked_ca_and_underlying_public_key_revoke_certificate
    revoked_by_ca = certificate(@ca_one, @host_one, 40, "by-ca")
    revoked_by_key = certificate(@ca_two, @host_two, 41, "by-key")
    not_revoked = certificate(@ca_two, @host_one, 42, "not-revoked")

    with_krl_file(
      explicit_section(@ca_three.to_blob),
      digest_section(Net::SSH::KRL::FINGERPRINT_SHA256_HASHES, 32,
                     Digest::SHA256.digest(@ca_one.to_blob)),
      digest_section(Net::SSH::KRL::FINGERPRINT_SHA1_HASHES, 20,
                     Digest::SHA1.digest(@host_two.to_blob))
    ) do |krl|
      revocation = Net::SSH::KRL.load_file(krl)

      assert revocation.revoked?(revoked_by_ca)
      assert revocation.revoked?(revoked_by_key)
      refute revocation.revoked?(not_revoked)
    end
  end

  def test_accept_new_and_local_tunnel_do_not_bypass_revocation
    key = Net::SSH::Buffer.new(@host_one.to_blob).read_key
    with_krl_file(explicit_section(key.to_blob)) do |krl|
      assert_raises(Net::SSH::HostKeyRevoked) do
        verify(Net::SSH::Verifiers::AcceptNew.new, key, krl)
      end

      session = session_for(key, krl, port: 2222, ip: "127.0.0.1")
      assert_raises(Net::SSH::HostKeyRevoked) do
        Net::SSH::Verifiers::AcceptNewOrLocalTunnel.new.verify(
          session: session, key: key, fingerprint: fingerprint(key)
        )
      end
    end
  end

  def test_never_and_plain_revoked_keys_file_do_not_bypass_revocation
    key = Net::SSH::Buffer.new(@host_one.to_blob).read_key
    cert = certificate(@ca_one, @host_one, 50, "plain-file")
    file = Tempfile.create(["revoked", ".pub"], Dir.pwd)
    begin
      file.binmode
      file.puts("#{key.ssh_type} #{[key.to_blob].pack('m0')} revoked-host")
      file.puts("#{@host_two.ssh_type} #{[@host_two.to_blob].pack('m0')} revoked-underlying")
      file.flush

      assert_raises(Net::SSH::HostKeyRevoked) do
        Net::SSH::Verifiers::Never.new.verify(
          session: session_for(key, file.path), key: key, fingerprint: fingerprint(key)
        )
      end
      assert_raises(Net::SSH::HostKeyRevoked) do
        Net::SSH::Verifiers::Never.new.verify(
          session: session_for(cert, file.path), key: cert, fingerprint: fingerprint(cert)
        )
      end
    ensure
      file.close
      File.unlink(file.path)
    end
  end

  def test_malformed_krl_and_unsupported_signature_section_fail
    Tempfile.create(["krl", ".bin"], Dir.pwd) do |file|
      file.binmode
      file.write(krl_blob(byte(6) + string("signature")))
      file.flush

      assert_raises(Net::SSH::KRL::ParseError) do
        Net::SSH::KRL.load_file(file.path)
      end
    end

    assert_raises(Net::SSH::KRL::ParseError) do
      Net::SSH::KRL.new("not a krl")
    end
  end

  def test_unknown_critical_extension_and_trailing_data_fail
    critical = extension_section("x-required", true, "value")
    assert_raises(Net::SSH::KRL::ParseError) do
      Net::SSH::KRL.new(krl_blob(critical))
    end

    critical_cert_extension = certificate_section(@ca_one, cert_extension_subsection("x-required", true, "value"))
    assert_raises(Net::SSH::KRL::ParseError) do
      Net::SSH::KRL.new(krl_blob(critical_cert_extension))
    end

    trailing = explicit_section(@host_one.to_blob) + "x".b
    assert_raises(Net::SSH::KRL::ParseError) do
      Net::SSH::KRL.new(krl_blob(trailing))
    end
  end

  def test_non_critical_unknown_extensions_are_ignored
    non_critical = extension_section("x-future", false, "value")
    known_key = explicit_section(@host_one.to_blob)
    assert Net::SSH::KRL.new(krl_blob(non_critical, known_key)).revoked?(@host_one)

    unknown_cert_subsection = subsection(128, "future")
    cert_section = certificate_section(@ca_one,
                                      serial_list_subsection(70),
                                      unknown_cert_subsection)
    cert = certificate(@ca_one, @host_one, 70, "future-subsection")
    assert Net::SSH::KRL.new(krl_blob(cert_section)).revoked?(cert)
  end

  def test_zero_serial_is_still_available_for_certificate_key_id_revocation
    cert = certificate(@ca_one, @host_one, 0, "zero-serial-id")
    krl_blob = krl_blob(certificate_section(@ca_one, key_id_subsection("zero-serial-id")))

    assert Net::SSH::KRL.new(krl_blob).revoked?(cert)
  end

  def test_missing_krl_and_malformed_revocation_file_fail_host_verification
    key = Net::SSH::Buffer.new(@host_one.to_blob).read_key
    missing = File.join(Dir.mktmpdir, "missing.krl")

    assert_raises(Net::SSH::HostKeyError) do
      verify(Net::SSH::Verifiers::AcceptNew.new, key, missing)
    end

    Tempfile.create(["bad", ".krl"], Dir.pwd) do |file|
      file.binmode
      file.write("broken")
      file.flush

      assert_raises(Net::SSH::HostKeyError) do
        verify(Net::SSH::Verifiers::AcceptNew.new, key, file.path)
      end
    end
  end

  private

  def certificate(ca, host_key, serial, key_id)
    cert = Net::SSH::Authentication::Certificate.new
    cert.nonce = "n" * 32
    cert.key = host_key
    cert.serial = serial
    cert.type = :host
    cert.key_id = key_id
    cert.valid_principals = [TARGET]
    cert.valid_after = Time.now - 60
    cert.valid_before = Time.now + 3600
    cert.critical_options = {}
    cert.extensions = {}
    cert.reserved = ""
    cert.sign!(ca)
    cert
  end

  def verify(verifier, key, path)
    verifier.verify(session: session_for(key, path), key: key, fingerprint: fingerprint(key))
  end

  def session_for(key, path, port: 22, ip: "1.2.3.4")
    host_keys = Net::SSH::HostKeys.new([], TARGET, Net::SSH::KnownHosts, {})
    OpenStruct.new(host_keys: host_keys, port: port, peer: { ip: ip },
                   options: { revoked_host_keys: path })
  end

  def fingerprint(key)
    Net::SSH::Authentication::PubKeyFingerprint.fingerprint(key.to_blob, "SHA256")
  end

  def krl_file(*sections)
    file = Tempfile.create(["revoked", ".krl"], Dir.pwd)
    file.binmode
    file.write(krl_blob(*sections))
    file.flush
    file
  end

  def with_krl_file(*sections)
    file = krl_file(*sections)
    yield file.path
  ensure
    file&.close
    File.unlink(file.path) if file
  end

  def krl_blob(*sections)
    Net::SSH::KRL::MAGIC + [Net::SSH::KRL::VERSION].pack("N") + [0].pack("Q>") + string("") + sections.join
  end

  def section(type, body)
    byte(type) + string(body)
  end

  def subsection(type, body)
    byte(type) + string(body)
  end

  def explicit_section(blob)
    section(Net::SSH::KRL::EXPLICIT_KEYS, string("") + string(blob))
  end

  def digest_section(type, length, digest)
    raise "bad digest length" unless digest.bytesize == length

    section(type, string("") + string(digest))
  end

  def certificate_section(ca, *subsections)
    section(Net::SSH::KRL::CERTIFICATES, string(ca.to_blob) + subsections.join)
  end

  def serial_list_subsection(*serials)
    subsection(Net::SSH::KRL::CERT_SERIALS_LIST, serials.map { |serial| [serial].pack("Q>") }.join)
  end

  def range_subsection(first, last)
    subsection(Net::SSH::KRL::CERT_SERIALS_RANGE, [first, last].pack("Q>Q>"))
  end

  def bitmap_subsection(first, bitmap)
    subsection(Net::SSH::KRL::CERT_SERIALS_BITMAP, [first].pack("Q>") + string(bitmap))
  end

  def key_id_subsection(key_id)
    subsection(Net::SSH::KRL::CERT_KEY_IDS, string(key_id))
  end

  def cert_extension_subsection(name, critical, contents)
    body = string("") + string(name) + byte(critical ? 1 : 0) + string(string(contents))
    subsection(Net::SSH::KRL::CERT_EXTENSIONS, body)
  end

  def extension_section(name, critical, contents)
    body = string("") + string(name) + byte(critical ? 1 : 0) + string(string(contents))
    section(Net::SSH::KRL::EXTENSIONS, body)
  end

  def byte(value)
    [value].pack("C")
  end

  def string(value)
    [value.bytesize].pack("N") + value.b
  end
end

class TestRevokedHostKeysConfig < NetSSHTest
  def test_translates_revoked_host_keys_config
    Dir.mktmpdir do |dir|
      config = File.join(dir, "config")
      File.write(config, "Host example\nRevokedHostKeys #{File.join(dir, 'revoked.krl')}\n")

      translated = Net::SSH::Config.for("example", [config])

      assert_equal File.join(dir, "revoked.krl"), translated[:revoked_host_keys]
    end
  end
end
