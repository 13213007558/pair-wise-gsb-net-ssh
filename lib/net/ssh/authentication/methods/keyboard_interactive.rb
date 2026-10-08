require 'net/ssh/prompt'
require 'net/ssh/authentication/challenge'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods
        # Implements the "keyboard-interactive" SSH authentication method.
        class KeyboardInteractive < Abstract
          USERAUTH_INFO_REQUEST  = 60
          USERAUTH_INFO_RESPONSE = 61

          # Attempt to authenticate the given user for the given service.
          def authenticate(next_service, username, password = nil)
            debug { "trying keyboard-interactive" }
            send_message(userauth_request(username, next_service, "keyboard-interactive", "", ""))

            @challenge_round = 0
            loop do
              message = session.next_message

              case message.type
              when USERAUTH_SUCCESS
                debug { "keyboard-interactive succeeded" }
                expire_active_challenge
                @prompter&.success
                return true
              when USERAUTH_FAILURE
                debug { "keyboard-interactive failed" }
                expire_active_challenge

                raise Net::SSH::Authentication::DisallowedMethod unless
                  message[:authentications].split(/,/).include? 'keyboard-interactive'

                return false unless interactive?

                password = nil
                debug { "retrying keyboard-interactive" }
                send_message(userauth_request(username, next_service, "keyboard-interactive", "", ""))
              when USERAUTH_INFO_REQUEST
                name = message.read_string
                instruction = message.read_string
                language = message.read_string
                debug { "keyboard-interactive info request" }

                prompts = []
                message.read_long.times do
                  prompts << KeyboardInteractiveChallenge::Prompt.new(message.read_string, message.read_bool)
                end

                responses = challenge_responses(name, instruction, language, prompts, password)

                # if the password failed the first time around, don't try
                # and use it on subsequent requests.
                password = nil

                msg = Buffer.from(:byte, USERAUTH_INFO_RESPONSE, :long, responses.length, :string, responses)
                send_message(msg)
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

          # Builds the list of responses for one USERAUTH_INFO_REQUEST. A
          # registered :keyboard_interactive_handler gets a structured
          # Challenge and may answer it asynchronously; otherwise the legacy
          # password/prompter behaviour is used.
          def challenge_responses(name, instruction, language, prompts, password)
            handler = @options[:keyboard_interactive_handler]
            return handler_responses(handler, name, instruction, language, prompts) if handler

            if password.nil? && interactive? && @prompter.nil?
              @prompter = prompt.start(type: 'keyboard-interactive', name: name, instruction: instruction)
            end

            prompts.map do |item|
              password || (@prompter && @prompter.ask(item.text, item.echo?))
            end
          end

          def handler_responses(handler, name, instruction, language, prompts)
            @active_challenge&.finish
            challenge = KeyboardInteractiveChallenge.new(@challenge_round += 1, name, instruction, language, prompts)
            @active_challenge = challenge

            debug { "dispatching keyboard-interactive challenge #{challenge.round} with #{prompts.length} prompt(s)" }
            handler.call(challenge)

            # A round with no prompts (e.g. an informational banner-style
            # request) is answered with an empty response immediately; the
            # caller is not expected to answer it, and it stays the current
            # challenge until auth succeeds or fails.
            prompts.empty? ? [] : challenge.take_answers
          end

          def expire_active_challenge
            @active_challenge&.finish
            @active_challenge = nil
          end
        end
      end
    end
  end
end
