require 'net/ssh/errors'
require 'net/ssh/verifiers/revocation'

module Net
  module SSH
    module Verifiers
      # This host key verifier simply allows every key it sees, without
      # any verification. This is simple, but very insecure because it
      # exposes you to MiTM attacks.
      class Never
        include Verifiers::Revocation

        # Returns true.
        def verify(arguments)
          verify_revocation!(arguments)
          true
        end

        def verify_signature(&block)
          true
        end
      end
    end
  end
end
