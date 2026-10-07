require 'strscan'
require 'openssl'
require 'delegate'
require 'tempfile'
require 'net/ssh/buffer'
require 'net/ssh/authentication/ed25519_loader'

module Net
  module SSH
    module HostKeyEntries
      # regular public key entry
      class PubKey < Delegator
        def initialize(key, comment: nil) # rubocop:disable Lint/MissingSuper
          @key = key
          @comment = comment
        end

        def ssh_type
          @key.ssh_type
        end

        def ssh_types
          [ssh_type]
        end

        def to_blob
          @key.to_blob
        end

        def __getobj__
          Kernel.warn("Calling Net::SSH::Buffer methods on HostKeyEntries PubKey is deprecated")
          @key
        end

        def matches_key?(server_key)
          @key.ssh_type == server_key.ssh_type && @key.to_blob == server_key.to_blob
        end
      end

      # @cert-authority entry
      class CertAuthority
        def ssh_types
          %w[
            ecdsa-sha2-nistp256-cert-v01@openssh.com
            ecdsa-sha2-nistp384-cert-v01@openssh.com
            ecdsa-sha2-nistp521-cert-v01@openssh.com
            ssh-ed25519-cert-v01@openssh.com
            ssh-rsa-cert-v01@openssh.com
            ssh-rsa-cert-v00@openssh.com
          ]
        end

        def initialize(key, comment: nil)
          @key = key
          @comment = comment
        end

        def matches_key?(server_key)
          if ssh_types.include?(server_key.ssh_type)
            server_key.signature_valid? && (server_key.signature_key.to_blob == @key.to_blob)
          else
            false
          end
        end

        # Returns true if the certificate lists no principals (unrestricted) or
        # if the given hostname matches a listed principal. Host-certificate
        # principals are shell-glob patterns, matching OpenSSH, whose
        # sshkey_cert_check_host passes wildcard_pattern=1 so principals like
        # "*.example.com" are matched with match_pattern rather than strcmp.
        def matches_principal?(server_key, hostname)
          server_key.valid_principals.empty? ||
            server_key.valid_principals.any? { |principal| File.fnmatch(principal, hostname) }
        end

        # Returns true if the certificate's validity window covers the current time.
        def matches_validity?(server_key)
          return false if server_key.valid_after && server_key.valid_after > Time.now
          return false if server_key.valid_before && server_key.valid_before < Time.now

          true
        end

        # Returns true if the certificate is a host certificate. A user
        # certificate (type :user) must never authenticate a host.
        def matches_type?(server_key)
          server_key.type == :host
        end

        # Returns true if every critical option in the certificate is one we can
        # enforce. net-ssh enforces none, so any critical option is unsupported
        # and, as OpenSSH does, must cause the certificate to be rejected.
        def critical_options_supported?(server_key)
          server_key.critical_options.empty?
        end
      end
    end

    # Represents the result of a search in known hosts
    # see search_for
    class HostKeys
      include Enumerable
      attr_reader :host

      def initialize(host_keys, host, known_hosts, options = {})
        @host_keys = host_keys
        @host = host
        @known_hosts = known_hosts
        @options = options
      end

      def add_host_key(key)
        @known_hosts.add(@host, key, @options)
        @host_keys.push(key)
      end

      def update_host_keys(keys, replace: false)
        keys = Array(keys)
        if @known_hosts.respond_to?(:update)
          @known_hosts.update(@host, keys, replace: replace, options: @options)
        else
          keys.each { |key| @known_hosts.add(@host, key, @options) }
        end
        if replace
          @host_keys.replace(keys)
        else
          keys.each do |key|
            @host_keys << key unless @host_keys.any? { |existing| existing.to_blob == key.to_blob }
          end
        end
      end

      def each(&block)
        @host_keys.each(&block)
      end

      def empty?
        @host_keys.empty?
      end

      # Returns the bare hostname, stripping port and IP portions from the
      # comma-separated host string used internally.
      #
      # Examples:
      #   "server.example.com"            => "server.example.com"
      #   "server.example.com,1.2.3.4"    => "server.example.com"
      #   "[server.example.com]:2222"      => "server.example.com"
      def hostname
        @host.split(",").first.gsub(/\[|\]:\d+/, "")
      end
    end

    # Searches an OpenSSH-style known-host file for a given host, and returns all
    # matching keys. This is used to implement host-key verification, as well as
    # to determine what key a user prefers to use for a given host.
    #
    # This is used internally by Net::SSH, and will never need to be used directly
    # by consumers of the library.
    class KnownHosts
      SUPPORTED_TYPE = %w[ssh-rsa ssh-dss
                          ecdsa-sha2-nistp256
                          ecdsa-sha2-nistp384
                          ecdsa-sha2-nistp521]

      SUPPORTED_TYPE.push('ssh-ed25519') if Net::SSH::Authentication::ED25519Loader::LOADED

      class << self
        # Searches all known host files (see KnownHosts.hostfiles) for all keys
        # of the given host. Returns an enumerable of keys found.
        def search_for(host, options = {})
          HostKeys.new(search_in(hostfiles(options), host, options), host, self, options)
        end

        # Search for all known keys for the given host, in every file given in
        # the +files+ array. Returns the list of keys.
        def search_in(files, host, options = {})
          files.flat_map { |file| KnownHosts.new(file).keys_for(host, options) }
        end

        # Looks in the given +options+ hash for the :user_known_hosts_file and
        # :global_known_hosts_file keys, and returns an array of all known
        # hosts files. If the :user_known_hosts_file key is not set, the
        # default is returned (~/.ssh/known_hosts and ~/.ssh/known_hosts2). If
        # :global_known_hosts_file is not set, the default is used
        # (/etc/ssh/ssh_known_hosts and /etc/ssh/ssh_known_hosts2).
        #
        # If you only want the user known host files, you can pass :user as
        # the second option.
        def hostfiles(options, which = :all)
          files = []

          files += Array(options[:user_known_hosts_file] || %w[~/.ssh/known_hosts ~/.ssh/known_hosts2]) if which == :all || which == :user

          if which == :all || which == :global
            files += Array(options[:global_known_hosts_file] || %w[/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2])
          end

          return files
        end

        # Looks in all user known host files (see KnownHosts.hostfiles) and tries to
        # add an entry for the given host and key to the first file it is able
        # to.
        def add(host, key, options = {})
          hostfiles(options, :user).each do |file|
            KnownHosts.new(file).add(host, key)
            return
          rescue SystemCallError
            # try the next hostfile
          end
        end

        def update(host, keys, replace: false, options: {})
          files = hostfiles(options, :user)
          source = files.find do |file|
            File.readable?(file) && KnownHosts.new(file).keys_for(host, options).any?
          end

          if source
            KnownHosts.new(source).update(host, keys, replace: replace)
          else
            keys.each { |key| add(host, key, options) }
          end
        end
      end

      # The host-key file name that this KnownHosts instance will use to search
      # for keys.
      attr_reader :source

      # Instantiate a new KnownHosts instance that will search the given known-hosts
      # file. The path is expanded file File.expand_path.
      def initialize(source)
        @source = File.expand_path(source)
      rescue ArgumentError
        @source = source
      end

      # Returns an array of all keys that are known to be associatd with the
      # given host. The +host+ parameter is either the domain name or ip address
      # of the host, or both (comma-separated). Additionally, if a non-standard
      # port is being used, it may be specified by putting the host (or ip, or
      # both) in square brackets, and appending the port outside the brackets
      # after a colon. Possible formats for +host+, then, are;
      #
      #   "net.ssh.test"
      #   "1.2.3.4"
      #   "net.ssh.test,1.2.3.4"
      #   "[net.ssh.test]:5555"
      #   "[1,2,3,4]:5555"
      #   "[net.ssh.test]:5555,[1.2.3.4]:5555
      def keys_for(host, options = {})
        keys = []
        return keys unless File.readable?(source)

        entries = host.split(/,/)
        host_name = entries[0]
        host_ip = entries[1]

        File.open(source) do |file|
          file.each_line do |line|
            if line.start_with?('@')
              marker, hosts, type, key_content, comment = line.split(' ')
            else
              marker = nil
              hosts, type, key_content, comment = line.split(' ')
            end

            # Skip empty line or one that is commented
            next if hosts.nil? || hosts.start_with?('#')

            hostlist = hosts.split(',')

            next unless SUPPORTED_TYPE.include?(type)

            found = hostlist.any? { |pattern| match(host_name, pattern) } || known_host_hash?(hostlist, entries)
            next unless found

            found = hostlist.include?(host_ip) if options[:check_host_ip] && entries.size > 1 && hostlist.size > 1
            next unless found

            blob = key_content.unpack("m*").first
            raw_key = Net::SSH::Buffer.new(blob).read_key

            keys <<
              if marker == "@cert-authority"
                HostKeyEntries::CertAuthority.new(raw_key, comment: comment)
              else
                HostKeyEntries::PubKey.new(raw_key, comment: comment)
              end
          end
        end

        keys
      end

      def match(host, pattern)
        if pattern.include?('*') || pattern.include?('?')
          # see man 8 sshd for pattern details
          pattern_regexp = pattern.split('*', -1).map do |x|
            x.split('?', -1).map do |y|
              Regexp.escape(y)
            end.join('.')
          end.join('.*')

          host =~ Regexp.new("\\A#{pattern_regexp}\\z")
        else
          host == pattern
        end
      end

      # Indicates whether one of the entries matches an hostname that has been
      # stored as a HMAC-SHA1 hash in the known hosts.
      def known_host_hash?(hostlist, entries)
        if hostlist.size == 1 && hostlist.first =~ /\A\|1(\|.+){2}\z/
          chunks = hostlist.first.split(/\|/)
          salt = chunks[2].unpack1("m")
          digest = OpenSSL::Digest.new('sha1')
          entries.each do |entry|
            hmac = OpenSSL::HMAC.digest(digest, salt, entry)
            return true if [hmac].pack("m").chomp == chunks[3]
          end
        end
        false
      end

      # Tries to append an entry to the current source file for the given host
      # and key. If it is unable to (because the file is not writable, for
      # instance), an exception will be raised.
      def add(host, key)
        File.open(source, "a") do |file|
          blob = [Net::SSH::Buffer.from(:key, key).to_s].pack("m*").gsub(/\s/, "")
          file.puts "#{host} #{key.ssh_type} #{blob}"
        end
      end

      def update(host, keys, replace: false)
        content = File.exist?(source) ? File.read(source) : ""
        updated = update_content(content, host, keys, replace)
        return false if updated == content

        write_atomically(updated)
        true
      end

      private

      def update_content(content, host, keys, replace)
        target_patterns = host.split(",")
        key_blobs = keys.map(&:to_blob)
        hashed = false
        hashed_patterns = []
        output = []
        content.lines(chomp: true).each do |line|
          parsed = parse_entry(line)
          if parsed.nil? || !target_entry?(parsed, target_patterns)
            output << line
            next
          end

          hashed ||= hashed_entry?(parsed)
          if hashed_entry?(parsed) && matched_hashed_pattern(parsed, target_patterns)
            hashed_patterns << { pattern: matched_hashed_pattern(parsed, target_patterns), hashed: parsed[:hosts] }
          end

          unless replace && removable_entry?(parsed, target_patterns) && !parsed[:marker] && !key_blobs.include?(parsed[:blob])
            output << line
          end
        end

        existing_target_blobs = output.filter_map do |line|
          parsed = parse_entry(line)
          parsed && target_entry?(parsed, target_patterns) ? parsed[:blob] : nil
        end

        new_keys = keys.reject { |key| existing_target_blobs.include?(key.to_blob) }
        new_keys.each do |key|
          new_entry_patterns(host, target_patterns, hashed, hashed_patterns).uniq.each do |pattern|
            output << format_entry(pattern, key)
          end
        end

        output.join("\n") + (content.end_with?("\n") || (content.empty? && !output.empty?) ? "\n" : "")
      end

      def parse_entry(line)
        return nil if line.empty? || line.start_with?('#')

        fields = line.split(' ', 5)
        return nil if fields.length < 3

        if fields.first.start_with?('@')
          marker, hosts, type, encoded_key, comment = fields
        else
          marker = nil
          hosts, type, encoded_key, comment = fields
        end

        return nil unless SUPPORTED_TYPE.include?(type)

        blob = encoded_key.unpack1("m*")
        Net::SSH::Buffer.new(blob).read_key
        {
          marker: marker,
          hosts: hosts,
          type: type,
          blob: blob,
          comment: comment
        }
      rescue StandardError
        nil
      end

      def target_entry?(entry, target_patterns)
        patterns = entry[:hosts].split(",")
        return true if patterns.length == 1 && target_patterns.include?(patterns.first)

        patterns == target_patterns || known_host_hash?(patterns, target_patterns)
      end

      def hashed_entry?(entry)
        entry[:hosts].split(",").one? && entry[:hosts].start_with?("|1|")
      end

      def matched_hashed_pattern(entry, target_patterns)
        return nil unless hashed_entry?(entry)

        target_patterns.find { |pattern| known_host_hash?(entry[:hosts].split(","), [pattern]) }
      end

      def removable_entry?(entry, target_patterns)
        patterns = entry[:hosts].split(",")
        hashed_entry?(entry) || patterns == target_patterns
      end

      def new_entry_patterns(host, target_patterns, hashed, existing_hashed_patterns)
        return [host] unless hashed

        existing_hashed_patterns.map { |item| item[:hashed] } +
          target_patterns.reject { |pattern| existing_hashed_patterns.any? { |item| item[:pattern] == pattern } }
                           .map { |pattern| hash_host(pattern) }
      end

      def format_entry(pattern, key)
        "#{pattern} #{key.ssh_type} #{encoded_key(key)}"
      end

      def encoded_key(key)
        [Net::SSH::Buffer.from(:key, key).to_s].pack("m*").gsub(/\s/, "")
      end

      def hash_host(pattern)
        salt = OpenSSL::Random.random_bytes(20)
        digest = OpenSSL::Digest.new('sha1')
        hmac = OpenSSL::HMAC.digest(digest, salt, pattern)
        "|1|#{[salt].pack('m0')}|#{[hmac].pack('m0')}"
      end

      def write_atomically(content)
        mode = File.exist?(source) ? File.stat(source).mode : nil
        Tempfile.create(File.basename(source), File.dirname(source)) do |file|
          file.write(content)
          file.chmod(mode) if mode
          file.close
          File.rename(file.path, source)
        end
      end
    end
  end
end
