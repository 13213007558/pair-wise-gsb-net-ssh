require_relative './common'
require 'digest'
require 'tempfile'

require 'net/ssh/buffer'
require 'net/ssh/krl'
require 'net/ssh/authentication/certificate'
require 'net/ssh/authentication/ed25519'

class TestKRL < NetSSHTest
  Buffer = Net::SSH::Buffer

  def test_revokes_explicit_public_key
    krl = build_krl(public_keys: [server_key])

    assert krl.revoked?(server_key)
    refute krl.revoked?(other_key)
  end

  def test_revokes_sha1_and_sha256_fingerprints
    sha1 = build_krl(sha1_hashes: [sha1_digest(server_key)])
    sha256 = build_krl(sha256_hashes: [sha256_digest(server_key)])

    assert sha1.revoked?(server_key)
    assert sha256.revoked?(server_key)
    refute sha1.revoked?(other_key)
    refute sha256.revoked?(other_key)
  end

  def test_revokes_certificate_key_id_with_ca_qualification
    revoked = certificate(ca_one, serial: 5, key_id: 'revoked-id')
    same_id_other_ca = certificate(ca_two, serial: 6, key_id: 'revoked-id')
    krl = build_krl(certificate_sections: [ca_one, [key_id_section(['revoked-id'])]])

    assert krl.revoked?(revoked)
    refute krl.revoked?(same_id_other_ca)
  end

  def test_revokes_certificate_serial_list
    revoked = certificate(ca_one, serial: 7)
    other_ca = certificate(ca_two, serial: 7)
    krl = build_krl(certificate_sections: [ca_one, [serial_list_section([7])]])

    assert krl.revoked?(revoked)
    refute krl.revoked?(other_ca)
  end

  def test_revokes_certificate_serial_ranges
    krl = build_krl(certificate_sections: [ca_one, [serial_range_section(10, 12)]])

    assert krl.revoked?(certificate(ca_one, serial: 10))
    assert krl.revoked?(certificate(ca_one, serial: 11))
    assert krl.revoked?(certificate(ca_one, serial: 12))
    refute krl.revoked?(certificate(ca_one, serial: 13))
    refute krl.revoked?(certificate(ca_two, serial: 11))
  end

  def test_revokes_certificate_serial_bitmap
    krl = build_krl(certificate_sections: [ca_one, [serial_bitmap_section(20, "\x0a")]])

    assert krl.revoked?(certificate(ca_one, serial: 21))
    assert krl.revoked?(certificate(ca_one, serial: 23))
    refute krl.revoked?(certificate(ca_one, serial: 22))
    refute krl.revoked?(certificate(ca_two, serial: 21))
  end

  def test_revokes_ca_public_key
    cert = certificate(ca_one, serial: 99, key_id: 'not-listed')
    krl = build_krl(public_keys: [ca_one.public_key])

    assert krl.revoked?(cert)
    refute krl.revoked?(certificate(ca_two, serial: 99, key_id: 'not-listed'))
  end

  def test_revokes_certificate_underlying_public_key
    cert = certificate(ca_one, serial: 100, key_id: 'not-listed')
    krl = build_krl(public_keys: [server_key])

    assert krl.revoked?(cert)
  end

  def test_explicit_certificate_entry_revokes_underlying_key_not_certificate_blob
    cert = certificate(ca_one, serial: 102, key_id: 'not-listed')
    krl = build_krl(public_keys: [cert])

    assert krl.revoked?(server_key)
    refute krl.revoked?(other_key)
  end

  def test_revoked_ca_hash_also_revokes_certificate
    cert = certificate(ca_one, serial: 101)
    krl = build_krl(sha256_hashes: [sha256_digest(ca_one.public_key)])

    assert krl.revoked?(cert)
    refute krl.revoked?(certificate(ca_two, serial: 101))
  end

  def test_rejects_unknown_critical_extension
    data = krl_data(extension_section('unknown', 'data', true))

    error = assert_raises(Net::SSH::KRL::ParseError) { Net::SSH::KRL.new(data) }
    assert_match(/unknown critical KRL extension/, error.message)
  end

  def test_rejects_unknown_critical_section
    data = krl_data(section(0x80 | 0x7f, Buffer.from(:raw, 'ignored').to_s))

    assert_raises(Net::SSH::KRL::ParseError) { Net::SSH::KRL.new(data) }
  end

  def test_rejects_signature_section
    signature = Buffer.from(
      :string, signing_key.ssh_signature_type,
      :string, 'signature'
    ).to_s

    assert_raises(Net::SSH::KRL::ParseError) do
      Net::SSH::KRL.new(krl_data(section(Net::SSH::KRL::SECTION_SIGNATURE, signature)))
    end
  end

  def test_rejects_corrupt_krl
    assert_raises(Net::SSH::KRL::ParseError) { Net::SSH::KRL.new('not a krl') }
    assert_raises(Net::SSH::KRL::ParseError) do
      Net::SSH::KRL.new(krl_data + 'tail')
    end

    corrupt_cert_section = section(
      Net::SSH::KRL::SECTION_CERTIFICATE,
      Buffer.from(:string, ca_one.public_key.to_blob, :byte, 0x7f, :string, '').to_s
    )
    assert_raises(Net::SSH::KRL::ParseError) do
      Net::SSH::KRL.new(krl_data(corrupt_cert_section))
    end
  end

  private

  def server_key
    @server_key ||= new_signing_key
  end

  def other_key
    @other_key ||= new_signing_key
  end

  def signing_key
    @signing_key ||= new_signing_key
  end

  def ca_one
    @ca_one ||= new_signing_key
  end

  def ca_two
    @ca_two ||= new_signing_key
  end

  def new_signing_key
    private_bytes = OpenSSL::Random.random_bytes(32)
    key = OpenSSL::PKey.new_raw_private_key('ED25519', private_bytes)
    SigningEd25519Key.new(private_bytes, key.raw_public_key)
  end

  def certificate(ca, serial:, key_id: 'host')
    cert = Net::SSH::Authentication::Certificate.new
    cert.nonce = OpenSSL::Random.random_bytes(32)
    cert.key = server_key.public_key
    cert.serial = serial
    cert.type = :host
    cert.key_id = key_id
    cert.valid_principals = []
    cert.valid_after = Time.at(0)
    cert.valid_before = Time.at(0xffffffffffffffff)
    cert.critical_options = {}
    cert.extensions = {}
    cert.reserved = ''
    cert.sign!(ca)
    cert
  end

  def sha1_digest(key)
    Digest::SHA1.digest(key.to_blob)
  end

  def sha256_digest(key)
    Digest::SHA256.digest(key.to_blob)
  end

  def build_krl(public_keys: [], sha1_hashes: [], sha256_hashes: [], certificate_sections: [])
    sections = []
    sections << section(Net::SSH::KRL::SECTION_PUBLIC_KEY, public_keys.map(&:to_blob).join) unless public_keys.empty?

    sections << section(Net::SSH::KRL::SECTION_PUBLIC_KEY_SHA1, sha1_hashes.join) unless sha1_hashes.empty?
    sections << section(Net::SSH::KRL::SECTION_PUBLIC_KEY_SHA256, sha256_hashes.join) unless sha256_hashes.empty?

    certificate_sections.each_slice(2) do |ca, cert_sections|
      body = Buffer.from(:string, ca.public_key.to_blob, :raw, cert_sections.join).to_s
      sections << section(Net::SSH::KRL::SECTION_CERTIFICATE, body)
    end

    Net::SSH::KRL.new(krl_data(*sections))
  end

  def krl_data(*sections)
    Buffer.from(
      :raw, Net::SSH::KRL::MAGIC,
      :long, Net::SSH::KRL::VERSION,
      :long, 0,
      :int64, 0,
      :string, '',
      :string, '',
      :raw, sections.join
    ).to_s
  end

  def section(type, body)
    Buffer.from(:byte, type, :string, body).to_s
  end

  def serial_list_section(serials)
    section(Net::SSH::KRL::CERT_SERIAL_LIST, Buffer.from(:int64, serials).to_s)
  end

  def serial_range_section(first, last)
    section(Net::SSH::KRL::CERT_SERIAL_RANGE, Buffer.from(:int64, [first, last]).to_s)
  end

  def serial_bitmap_section(offset, bitmap)
    section(Net::SSH::KRL::CERT_SERIAL_BITMAP, Buffer.from(:int64, offset, :string, bitmap).to_s)
  end

  def key_id_section(ids)
    section(Net::SSH::KRL::CERT_KEY_ID, Buffer.from(:string, ids).to_s)
  end

  def extension_section(name, data, critical)
    section(
      Net::SSH::KRL::SECTION_EXTENSION,
      Buffer.from(:string, name, :string, data, :bool, critical).to_s
    )
  end

  class SigningEd25519Key
    include Net::SSH::Authentication::ED25519
    ED25519 = Net::SSH::Authentication::ED25519

    def initialize(private_key_bytes, public_key_bytes)
      @private_key_bytes = private_key_bytes
      @public_key_bytes = public_key_bytes
      @sign_key = ED25519.new_private_key(private_key_bytes)
    end

    def ssh_type
      'ssh-ed25519'
    end

    alias ssh_signature_type ssh_type

    def to_blob
      Net::SSH::Buffer.from(:string, ssh_type, :string, @public_key_bytes).to_s
    end

    def public_key
      Net::SSH::Authentication::ED25519::PubKey.new(@public_key_bytes)
    end

    def ssh_do_sign(data, _signature_algorithm = nil)
      ED25519.sign(@sign_key, data)
    end
  end
end
