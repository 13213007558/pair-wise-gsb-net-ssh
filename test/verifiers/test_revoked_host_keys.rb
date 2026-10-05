require 'common'
require 'ostruct'
require 'tempfile'

require 'net/ssh/buffer'
require 'net/ssh/krl'
require 'net/ssh/verifiers/always'
require 'net/ssh/verifiers/accept_new'

class TestRevokedHostKeys < NetSSHTest
  Buffer = Net::SSH::Buffer

  def test_always_rejects_revoked_key
    with_revocation_file(krl_for(key)) do |path|
      assert_raises(Net::SSH::HostKeyMismatch) { verify(Net::SSH::Verifiers::Always.new, key, path) }
    end
  end

  def test_accept_new_does_not_bypass_revocation
    with_revocation_file(krl_for(key)) do |path|
      error = assert_raises(Net::SSH::HostKeyMismatch) do
        verify(Net::SSH::Verifiers::AcceptNew.new, key, path)
      end
      assert_match(/has been revoked/, error.message)
    end
  end

  def test_missing_revocation_file_is_not_ignored
    error = assert_raises(Net::SSH::HostKeyMismatch) do
      verify(Net::SSH::Verifiers::AcceptNew.new, key, '/path/that/does/not/exist.krl')
    end

    assert_match(/not readable/, error.message)
  end

  def test_corrupt_revocation_file_is_rejected
    Tempfile.create('revoked.krl') do |file|
      file.write('corrupt')
      file.flush

      error = assert_raises(Net::SSH::HostKeyMismatch) do
        verify(Net::SSH::Verifiers::AcceptNew.new, key, file.path)
      end
      assert_match(/is invalid/, error.message)
    end
  end

  private

  def key
    @key ||= begin
      asn1 = OpenSSL::ASN1::Sequence(
        [
          OpenSSL::ASN1::Integer(0x7766554433221100),
          OpenSSL::ASN1::Integer(0xffeeddccbbaa9988)
        ]
      )
      OpenSSL::PKey::RSA.new(asn1.to_der)
    end
  end

  def krl_for(key)
    section_body = key.to_blob
    data = Buffer.from(
      :raw, Net::SSH::KRL::MAGIC,
      :long, Net::SSH::KRL::VERSION,
      :long, 0,
      :int64, 0,
      :string, '',
      :string, '',
      :byte, Net::SSH::KRL::SECTION_PUBLIC_KEY,
      :string, section_body
    ).to_s
    data
  end

  def with_revocation_file(data)
    Tempfile.create('revoked.krl') do |file|
      file.binmode
      file.write(data)
      file.flush
      yield(file.path)
    end
  end

  def verify(verifier, key, revocation_file)
    host_keys = []
    host_keys.define_singleton_method(:host) { 'example.com' }
    options = OpenStruct.new(revoked_host_keys: revocation_file)
    session = OpenStruct.new(host_keys: host_keys, options: options)
    verifier.verify(session: session, key: key, fingerprint: 'SHA256:test')
  end
end
