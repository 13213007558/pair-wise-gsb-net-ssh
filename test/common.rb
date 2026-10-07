$LOAD_PATH.unshift "#{File.dirname(__FILE__)}/../lib"

if ENV["CI"]
  unless Gem.win_platform?
    require 'simplecov'
    SimpleCov.start

    #    require 'codecov'
    #    SimpleCov.formatter = SimpleCov::Formatter::Codecov
  end
end

require 'minitest'
require 'mocha/minitest'
require 'net/ssh/buffer'
require 'net/ssh/config'
require 'net/ssh/loggable'
require 'net/ssh/packet'
require 'net/ssh/transport/session'
require 'ostruct'

require 'minitest/autorun'

# clear the default files out so that tests don't get confused by existing
# SSH config files.
$_original_config_default_files = Net::SSH::Config.default_files.dup # rubocop:disable Style/GlobalVars
Net::SSH::Config.default_files.clear

# Ensures SSH_AUTH_SOCK set outside of test scenario (e.g. on dev's machine) isn't messing up test assertions
original_ssh_auth_sock, ENV['SSH_AUTH_SOCK'] = ENV['SSH_AUTH_SOCK'], nil
Minitest.after_run { ENV['SSH_AUTH_SOCK'] = original_ssh_auth_sock }

def with_restored_default_files(&block)
  act_default_files = Net::SSH::Config.default_files.dup
  begin
    Net::SSH::Config.default_files.clear
    Net::SSH::Config.default_files.concat($_original_config_default_files) # rubocop:disable Style/GlobalVars
    yield
  ensure
    Net::SSH::Config.default_files.clear
    Net::SSH::Config.default_files.concat(act_default_files)
  end
end

def P(*args)
  Net::SSH::Packet.new(Net::SSH::Buffer.from(*args))
end

# Builds an openssh-key-v1 private key container (PEM armored) holding the
# given entries. Each entry is a hash with a :comment and either
# :type => "ssh-ed25519" with :private_key (32 byte seed) and :public_key,
# or :type => "ssh-rsa" with :key (an OpenSSL::PKey::RSA).
# Supports the "none" cipher or bcrypt kdf with any supported cipher when
# a password is given. Set :corrupt_padding to write invalid padding bytes
# or :tamper_public_keys to make the outer public keys not match the
# private key material.
def build_openssh_key_container(entries, cipher: "none", password: nil, rounds: 16,
                                corrupt_padding: false, tamper_public_keys: false)
  check = rand(0xffffffff)
  plain = Net::SSH::Buffer.from(:long, check, :long, check)
  public_keys = entries.map { |entry| openssh_container_public_blob(entry) }
  entries.each do |entry|
    case entry[:type]
    when "ssh-ed25519"
      plain.write_mstring("ssh-ed25519".dup)
      plain.write_string(entry[:public_key])
      plain.write_string(entry[:private_key] + entry[:public_key])
    when "ssh-rsa"
      key = entry[:key]
      plain.write_mstring("ssh-rsa".dup)
      plain.write_bignum(key.n)
      plain.write_bignum(key.e)
      plain.write_bignum(key.d)
      plain.write_bignum(key.q.mod_inverse(key.p))
      plain.write_bignum(key.p)
      plain.write_bignum(key.q)
    else
      raise "unsupported test key type: #{entry[:type]}"
    end
    plain.write_string(entry[:comment])
  end

  if cipher == "none"
    kdfname = "none"
    kdfopts = ""
    _keylen, blocksize, = Net::SSH::Transport::CipherFactory.get_lengths(cipher, iv_len: true)
    blocksize = 8 if blocksize.zero?
  else
    require 'bcrypt_pbkdf'
    kdfname = "bcrypt"
    salt = Random.bytes(16)
    kdfopts = Net::SSH::Buffer.from(:string, salt, :long, rounds).to_s
    keylen, blocksize, ivlen = Net::SSH::Transport::CipherFactory.get_lengths(cipher, iv_len: true)
    key = BCryptPbkdf.key(password, salt, keylen + ivlen, rounds)
  end

  padlen = blocksize - (plain.length % blocksize)
  padlen += blocksize if padlen.zero?
  padding = (1..padlen).map { |i| i % 256 }
  padding[-1] = (padding.last + 1) % 256 if corrupt_padding
  plain.write(padding.pack("C*"))

  if cipher == "none"
    encrypted = plain.to_s
  else
    encryptor = Net::SSH::Transport::CipherFactory.get(
      cipher, key: key[0...keylen], iv: key[keylen...(keylen + ivlen)], encrypt: true
    )
    encrypted = encryptor.update(plain.to_s) + encryptor.final
  end

  public_keys = public_keys.map { "tampered".b } if tamper_public_keys

  blob = Net::SSH::Buffer.new
  blob.write("openssh-key-v1\0")
  blob.write_mstring(cipher.dup)
  blob.write_mstring(kdfname.dup)
  blob.write_string(kdfopts)
  blob.write_long(public_keys.size)
  public_keys.each { |public_key| blob.write_string(public_key) }
  blob.write_string(encrypted)

  "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
    [blob.to_s].pack("m0").scan(/.{1,70}/).join("\n") +
    "\n-----END OPENSSH PRIVATE KEY-----\n"
end

def openssh_container_public_blob(entry)
  case entry[:type]
  when "ssh-ed25519"
    Net::SSH::Buffer.from(:mstring, "ssh-ed25519".dup, :string, entry[:public_key]).to_s
  when "ssh-rsa"
    Net::SSH::Buffer.from(:mstring, "ssh-rsa".dup, :bignum, entry[:key].e, :bignum, entry[:key].n).to_s
  else
    raise "unsupported test key type: #{entry[:type]}"
  end
end

def ed25519_container_entry(comment)
  seed = Random.bytes(Net::SSH::Authentication::ED25519::KEY_BYTES)
  public_key = Net::SSH::Authentication::ED25519.new_private_key(seed).raw_public_key
  { type: "ssh-ed25519", private_key: seed, public_key: public_key, comment: comment }
end

# DH key generate with OpenSSL::PKey::DH.new(512).to_pem
def dh_512bits_bn
  OpenSSL::PKey::DH.new(
    <<~DH_KEY
      -----BEGIN DH PARAMETERS-----
      MEYCQQDkZMgCTieW40x/bmCpf6m1XHERNnyOodot21UsJkCidr+T6aAcy/Oz4mWo
      aYudmZZLQz7jhz0Ut2VQUw0Nz033AgEC
      -----END DH PARAMETERS-----
    DH_KEY
  ).p
end

class NetSSHTest < Minitest::Test
  def assert_nothing_raised(&block)
    yield
  end

  def assert_not_nil(obj, msg = nil)
    refute_nil obj, msg
  end
end

class MockPrompt
  def start(info)
    @info = info
    self
  end

  def ask(message, echo)
    _ask(message, @info, echo)
  end

  def success; end
end

class MockTransport < Net::SSH::Transport::Session
  class BlockVerifier
    def initialize(block)
      @block = block
    end

    def verify(data)
      @block.call(data)
    end

    def verify_signature(&block)
      yield
    end
  end

  attr_reader :host_key_verifier
  attr_accessor :host_as_string
  attr_accessor :server_version

  attr_reader :client_options
  attr_reader :server_options
  attr_reader :hints, :queue

  attr_accessor :mock_enqueue

  def initialize(options = {})
    @options = options
    self.logger = options[:logger]
    self.host_as_string = "net.ssh.test,127.0.0.1"
    self.server_version = OpenStruct.new(version: "SSH-2.0-Ruby/Net::SSH::Test")
    @expectations = []
    @queue = []
    @hints = {}
    @socket = options[:socket]
    @algorithms = OpenStruct.new(session_id: "abcxyz123")
    verifier { |_data| true }
  end

  def send_message(message)
    buffer = Net::SSH::Buffer.new(message.to_s)
    if @expectations.empty?
      raise "got #{message.to_s.inspect} but was not expecting anything"
    else
      block = @expectations.shift
      block.call(self, Net::SSH::Packet.new(buffer))
    end
  end

  def enqueue_message(message)
    if mock_enqueue
      send_message(message)
    else
      super
    end
  end

  def closed?
    false
  end

  def poll_message
    @queue.shift
  end

  def next_message
    @queue.shift or raise "expected a message from the server but nothing was ready to send"
  end

  def return(type, *args)
    @queue << P(:byte, type, *args)
  end

  def expect(&block)
    @expectations << block
  end

  def expect!
    expect {}
  end

  def verifier(&block)
    @host_key_verifier = BlockVerifier.new(block)
  end

  def configure_client(options)
    @client_options = options
  end

  def configure_server(options)
    @server_options = options
  end

  def hint(name, value = true)
    @hints[name] = value
  end
end
