require 'net/ssh/krl'

module Net
  module SSH
    module Verifiers
      module Revocation
        private

        def verify_revocation!(arguments)
          session = arguments[:session]
          options = session.respond_to?(:options) ? session.options : nil
          paths = options && options[:revoked_host_keys]
          return if paths.nil?

          Array(paths).flat_map { |path| path.to_s.split(/\s+/) }.each do |path|
            next if path.empty? || path == "none"

            revocation_list = KRL.load_file(File.expand_path(path))
            next unless revocation_list.revoked?(arguments[:key])

            host = session.respond_to?(:host_keys) ? session.host_keys.host : session.inspect
            exception = HostKeyRevoked.new("fingerprint #{arguments[:fingerprint]} " \
                                         "has been revoked for #{host.inspect}")
            exception.data = arguments
            raise exception
          end
        rescue KRL::ParseError => e
          exception = HostKeyError.new(e.message)
          exception.data = arguments
          raise exception
        end
      end
    end
  end
end
