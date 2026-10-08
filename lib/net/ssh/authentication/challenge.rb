require 'thread'
require 'net/ssh/errors'

module Net
  module SSH
    module Authentication
      # Base error for problems reported while answering a
      # keyboard-interactive challenge.
      class ChallengeError < Net::SSH::Exception
      end

      # Raised when a caller tries to answer a challenge that no longer
      # represents the current round of authentication. Answers to expired
      # challenges are never written to the connection.
      class ChallengeExpired < ChallengeError
      end

      # Raised by Challenge#cancel to signal that the user aborted the
      # authentication. No USERAUTH_INFO_RESPONSE is sent for a cancelled
      # challenge.
      class ChallengeCanceled < ChallengeError
      end

      # A single round of keyboard-interactive authentication as described
      # by USERAUTH_INFO_REQUEST. The challenge is handed to the
      # :keyboard_interactive_handler callback (see Net::SSH.start) without
      # blocking the packet-reading loop. The caller may answer it later via
      # #respond or abort authentication with #cancel.
      #
      # A challenge keeps the server-provided #name, #instruction and
      # #language, together with the list of #prompts. Each prompt is a
      # Net::SSH::Authentication::KeyboardInteractiveChallenge::Prompt with the
      # question text and its +echo?+ flag.
      class KeyboardInteractiveChallenge
        # A single prompt in a keyboard-interactive challenge.
        Prompt = Struct.new(:text, :echo) do
          def echo?
            echo
          end

          def inspect
            "#<#{self.class} text=#{text.inspect} echo=#{echo}>"
          end
        end

        # @return [Integer] 1-based round of authentication this challenge
        #   belongs to.
        attr_reader :round

        # @return [String] the name supplied by the server.
        attr_reader :name

        # @return [String] the instruction supplied by the server.
        attr_reader :instruction

        # @return [String] the RFC 3066 language tag supplied by the server.
        attr_reader :language

        # @return [Array<Prompt>] the questions asked in this round, each
        #   carrying its echo flag.
        attr_reader :prompts

        # :nodoc:
        def initialize(round, name, instruction, language, prompts)
          @round = round
          @name = name
          @instruction = instruction
          @language = language
          @prompts = prompts
          @answers_queue = Queue.new
          @mutex = Mutex.new
          @state = :pending
        end

        # @return [Boolean] whether the challenge is still waiting for an
        #   answer.
        def pending?
          @mutex.synchronize { @state == :pending }
        end

        # @return [Boolean] whether the caller aborted the challenge.
        def canceled?
          @mutex.synchronize { @state == :canceled }
        end

        # @return [Boolean] whether the round this challenge belongs to is no
        #   longer current (a newer challenge arrived, or authentication
        #   finished).
        def expired?
          @mutex.synchronize { @state == :expired }
        end

        # Submit the answers for this round. Exactly one answer per prompt is
        # required; a wrong count leaves the challenge pending so the caller
        # may retry, and nothing is sent to the server.
        #
        # @param answers [Array<String>] one answer per prompt.
        # @raise [ChallengeExpired] if the challenge was cancelled or belongs
        #   to an old round.
        # @raise [ArgumentError] if the number of answers does not match the
        #   number of prompts.
        def respond(*answers)
          answers = answers.flatten
          @mutex.synchronize do
            raise ChallengeExpired, "challenge for round #{round} is #{@state}" unless @state == :pending

            unless answers.length == prompts.length
              raise ArgumentError,
                    "expected #{prompts.length} answer(s) but got #{answers.length}"
            end

            @state = :answered
            @answers_queue << answers
          end
          true
        end

        # Abort authentication for this round. No response packet is written
        # to the connection and ChallengeCanceled is raised from the
        # authentication loop.
        def cancel
          @mutex.synchronize do
            return false unless @state == :pending

            @state = :canceled
            @answers_queue << :canceled
            true
          end
        end

        # :nodoc:
        # Mark the challenge as no longer answerable because a newer round
        # started or authentication finished.
        def expire
          @mutex.synchronize do
            return false unless @state == :pending

            @state = :expired
            true
          end
        end

        # :nodoc:
        # Authentication finished (success or failure): pending and answered
        # challenges can no longer be used. Cancelled challenges keep their
        # state.
        def finish
          @mutex.synchronize do
            return false unless %i[pending answered].include?(@state)

            @state = :expired
            true
          end
        end

        # :nodoc:
        # Blocks the authentication loop until the caller answers or cancels
        # the challenge.
        def take_answers
          outcome = @answers_queue.pop
          raise ChallengeCanceled, "keyboard-interactive authentication was cancelled by the user" if outcome == :canceled

          outcome
        end

        # Answers are deliberately excluded so they never reach a log.
        def inspect
          "#<#{self.class} round=#{round} name=#{name.inspect} " \
            "instruction=#{instruction.inspect} language=#{language.inspect} " \
            "prompts=#{prompts.inspect} state=#{state}>"
        end

        # Answers are deliberately excluded so they never reach a log.
        alias to_s inspect

        private

        attr_reader :state
      end
    end
  end
end
