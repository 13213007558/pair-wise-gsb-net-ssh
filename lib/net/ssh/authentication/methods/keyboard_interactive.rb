require 'net/ssh/prompt'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods
        # Implements the "keyboard-interactive" SSH authentication method.
        class KeyboardInteractive < Abstract
          USERAUTH_INFO_REQUEST  = 60
          USERAUTH_INFO_RESPONSE = 61

          # A structured representation of a single keyboard-interactive
          # challenge (SSH_MSG_USERAUTH_INFO_REQUEST) issued by the server.
          #
          # Challenges are handed to the caller via the
          # :keyboard_interactive_challenge_handler option, so the answers
          # can be collected and submitted later with #submit, instead of
          # blocking the packet processing loop. A challenge writes to the
          # connection only when #submit accepts the answers; submissions
          # for stale (expired), cancelled, or already answered challenges,
          # and submissions whose answer count does not match the number of
          # prompts, are ignored and never reach the connection. Answers
          # are neither logged nor retained by the challenge.
          class Challenge
            # A single prompt of a keyboard-interactive challenge.
            class Prompt
              # the prompt text, as sent by the server
              attr_reader :text

              def initialize(text, echo)
                @text = text
                @echo = echo ? true : false
              end

              # whether the user's input may be echoed while typing
              def echo?
                @echo
              end
            end

            # the name, instruction and language tag sent by the server
            # (any of them may be an empty string)
            attr_reader :name, :instruction, :language

            # the list of Prompt objects the server wants answers for
            attr_reader :prompts

            def initialize(name:, instruction:, language:, prompts:, &on_submit) # :nodoc:
              @name = name
              @instruction = instruction
              @language = language
              @prompts = prompts
              @on_submit = on_submit
              @state = :pending
              @lock = Mutex.new
            end

            # The current state of the challenge: :pending (waiting for the
            # caller), :submitted (answers accepted and sent), :cancelled
            # (aborted by the caller) or :expired (invalidated because the
            # authentication exchange moved on or finished).
            def state
              @lock.synchronize { @state }
            end

            def pending?
              state == :pending
            end

            def submitted?
              state == :submitted
            end

            def cancelled?
              state == :cancelled
            end

            def expired?
              state == :expired
            end

            # Submits +answers+ for this challenge. The answers are written
            # to the connection only when the challenge is still pending and
            # the number of answers matches the number of prompts; in every
            # other case nothing is written and false is returned.
            def submit(answers)
              answers = Array(answers)
              @lock.synchronize do
                return false unless @state == :pending
                return false unless answers.length == @prompts.length

                @state = :submitted
              end
              @on_submit.call(answers)
              true
            end

            # Cancels the challenge, e.g. when the user aborts the prompt.
            # A cancelled challenge never writes to the connection. Returns
            # true when the challenge was still pending.
            def cancel
              transition_to(:cancelled)
            end

            # Invalidates a still-pending challenge, e.g. when the
            # authentication exchange succeeded, failed, or moved on to a
            # newer challenge. :nodoc:
            def expire!
              transition_to(:expired)
            end

            private

            def transition_to(new_state)
              @lock.synchronize do
                return false unless @state == :pending

                @state = new_state
              end
              true
            end
          end

          # Attempt to authenticate the given user for the given service.
          #
          # When the :keyboard_interactive_challenge_handler option is set
          # (and no password was given), each server challenge is wrapped in
          # a Challenge and passed to the handler instead of prompting
          # inline, so the caller may submit the answers later via
          # Challenge#submit or abort the exchange via Challenge#cancel.
          def authenticate(next_service, username, password = nil)
            debug { "trying keyboard-interactive" }
            send_message(userauth_request(username, next_service, "keyboard-interactive", "", ""))

            prompter = nil
            challenge = nil
            loop do
              message = session.next_message
              raise_if_cancelled(challenge)

              case message.type
              when USERAUTH_SUCCESS
                debug { "keyboard-interactive succeeded" }
                prompter.success if prompter
                challenge.expire! if challenge
                return true
              when USERAUTH_FAILURE
                debug { "keyboard-interactive failed" }
                challenge.expire! if challenge
                challenge = nil

                raise Net::SSH::Authentication::DisallowedMethod unless
                  message[:authentications].split(/,/).include? 'keyboard-interactive'

                return false unless interactive?

                password = nil
                debug { "retrying keyboard-interactive" }
                send_message(userauth_request(username, next_service, "keyboard-interactive", "", ""))
              when USERAUTH_INFO_REQUEST
                name = message.read_string
                instruction = message.read_string
                debug { "keyboard-interactive info request" }

                if password.nil? && interactive? && prompter.nil? && challenge_handler.nil?
                  prompter = prompt.start(type: 'keyboard-interactive', name: name, instruction: instruction)
                end

                language = message.read_string
                prompts = []
                message.read_long.times do
                  prompts << Challenge::Prompt.new(message.read_string, message.read_bool)
                end

                if password.nil? && challenge_handler
                  challenge.expire! if challenge
                  challenge = build_challenge(name, instruction, language, prompts)
                  debug { "keyboard-interactive challenge with #{prompts.length} prompt(s) handed to caller" }
                  challenge_handler.call(challenge)
                  raise_if_cancelled(challenge)
                else
                  responses = prompts.map { |item| password || (prompter && prompter.ask(item.text, item.echo?)) }

                  # if the password failed the first time around, don't try
                  # and use it on subsequent requests.
                  password = nil

                  msg = Buffer.from(:byte, USERAUTH_INFO_RESPONSE, :long, responses.length, :string, responses)
                  send_message(msg)
                end
              else
                raise Net::SSH::Exception, "unexpected reply in keyboard interactive: #{message.type} (#{message.inspect})"
              end
            end
          end

          def interactive?
            options = session.transport.options || {}
            !options[:non_interactive]
          end

          private

          # The caller-provided handler for structured challenges, if any.
          def challenge_handler
            @options[:keyboard_interactive_challenge_handler]
          end

          # Wraps a server challenge in a Challenge object whose accepted
          # submissions are written to the connection as
          # SSH_MSG_USERAUTH_INFO_RESPONSE. The answers are passed straight
          # to the connection and are never logged.
          def build_challenge(name, instruction, language, prompts)
            Challenge.new(name: name, instruction: instruction, language: language, prompts: prompts) do |answers|
              send_message(Buffer.from(:byte, USERAUTH_INFO_RESPONSE, :long, answers.length, :string, answers))
            end
          end

          # Aborts the authentication exchange when the caller cancelled the
          # current challenge instead of submitting answers for it.
          def raise_if_cancelled(challenge)
            return unless challenge && challenge.cancelled?

            debug { "keyboard-interactive challenge cancelled" }
            raise Net::SSH::Authentication::Cancelled, "keyboard-interactive authentication was cancelled"
          end
        end
      end
    end
  end
end
