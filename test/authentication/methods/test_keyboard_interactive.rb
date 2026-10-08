require_relative '../../common'
require 'logger'
require 'net/ssh/authentication/methods/keyboard_interactive'
require 'net/ssh/authentication/session'
require_relative 'common'

module Authentication
  module Methods
    class TestKeyboardInteractive < NetSSHTest
      include Common

      USERAUTH_INFO_REQUEST  = 60
      USERAUTH_INFO_RESPONSE = 61

      def setup
        reset_subject({}) if defined? @subject && !@subject.options.empty?
      end

      def test_authenticate_should_raise_if_keyboard_interactive_disallowed
        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert_equal "jamis", packet.read_string
          assert_equal "ssh-connection", packet.read_string
          assert_equal "keyboard-interactive", packet.read_string
          assert_equal "", packet.read_string # language tags
          assert_equal "", packet.read_string # submethods

          t.return(USERAUTH_FAILURE, :string, "password")
        end

        assert_raises Net::SSH::Authentication::DisallowedMethod do
          subject.authenticate("ssh-connection", "jamis")
        end
      end

      def test_authenticate_should_be_false_if_given_password_is_not_accepted
        reset_subject(non_interactive: true)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 1, packet2.read_long
            assert_equal "the-password", packet2.read_string
            t2.return(USERAUTH_FAILURE, :string, "keyboard-interactive")
          end
        end

        assert_equal false, subject.authenticate("ssh-connection", "jamis", "the-password")
      end

      def test_authenticate_should_be_true_if_given_password_is_accepted
        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", "the-password")
      end

      def test_authenticate_should_duplicate_password_as_needed_to_fill_request
        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 2, :string, "Password:", :bool, false, :string, "Again:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 2, packet2.read_long
            assert_equal "the-password", packet2.read_string
            assert_equal "the-password", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", "the-password")
      end

      def test_authenticate_should_not_prompt_for_input_when_in_non_interactive_mode
        reset_subject(non_interactive: true)
        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 2, :string, "Name:", :bool, true, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 2, packet2.read_long
            assert_equal "", packet2.read_string
            assert_equal "", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
      end

      def test_authenticate_should_prompt_for_input_when_password_is_not_given
        prompt = MockPrompt.new
        prompt.expects(:_ask).with("Name:", anything, true).returns("name")
        prompt.expects(:_ask).with("Password:", anything, false).returns("password")
        reset_subject(password_prompt: prompt)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 2, :string, "Name:", :bool, true, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 2, packet2.read_long
            assert_equal "name", packet2.read_string
            assert_equal "password", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
      end

      def test_structured_handler_two_round_auth
        received = []
        handler = lambda do |challenge|
          received << challenge
          Thread.new do
            case challenge.round
            when 1
              challenge.respond("the-password")
            when 2
              challenge.respond("otp-code")
            end
          end
        end
        reset_subject(keyboard_interactive_handler: handler)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "First", :string, "enter password",
                   :string, "en-US", :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 1, packet2.read_long
            assert_equal "the-password", packet2.read_string
            t2.return(USERAUTH_INFO_REQUEST, :string, "Second", :string, "enter otp",
                      :string, "en-GB", :long, 1, :string, "Code:", :bool, false)
            t2.expect do |t3, packet3|
              assert_equal USERAUTH_INFO_RESPONSE, packet3.type
              assert_equal 1, packet3.read_long
              assert_equal "otp-code", packet3.read_string
              t3.return(USERAUTH_SUCCESS)
            end
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
        assert_equal 2, received.length
        assert_equal ["First", "Second"], received.map(&:name)
        assert_equal ["enter password", "enter otp"], received.map(&:instruction)
        assert_equal ["en-US", "en-GB"], received.map(&:language)
        assert_equal [[false], [false]], received.map { |c| c.prompts.map(&:echo?) }
        received.each { |challenge| assert challenge.expired? }
      end

      def test_structured_handler_keeps_echo_flags
        seen_challenge = nil
        handler = lambda do |challenge|
          seen_challenge = challenge
          Thread.new { challenge.respond("name", "secret") }
        end
        reset_subject(keyboard_interactive_handler: handler)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "",
                   :long, 2, :string, "Name:", :bool, true, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 2, packet2.read_long
            assert_equal "name", packet2.read_string
            assert_equal "secret", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
        assert_equal [true, false], seen_challenge.prompts.map(&:echo?)
      end

      def test_structured_handler_zero_prompt_round_answers_empty_immediately
        received = []
        handler = lambda do |challenge|
          received << challenge
        end
        reset_subject(keyboard_interactive_handler: handler)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "Notice", :string, "just info",
                   :string, "", :long, 0)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 0, packet2.read_long
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
        assert_equal 1, received.length
        assert_equal "Notice", received.first.name
        refute received.first.pending?
        assert_raises(Net::SSH::Authentication::ChallengeExpired) do
          received.first.respond
        end
      end

      def test_structured_handler_cancel_sends_nothing_and_raises
        canceled_challenge = nil
        handler = lambda do |challenge|
          canceled_challenge = challenge
          Thread.new { challenge.cancel }
        end
        reset_subject(keyboard_interactive_handler: handler)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "",
                   :long, 1, :string, "Password:", :bool, false)
          # No USERAUTH_INFO_RESPONSE is expected; MockTransport raises if one
          # is sent.
        end

        assert_raises Net::SSH::Authentication::ChallengeCanceled do
          subject.authenticate("ssh-connection", "jamis", nil)
        end
        assert canceled_challenge.canceled?
        assert_raises(Net::SSH::Authentication::ChallengeExpired) do
          canceled_challenge.respond("late")
        end
      end

      def test_structured_handler_wrong_answer_count_does_not_write_to_connection
        challenge_ref = nil
        handler = lambda do |challenge|
          challenge_ref = challenge
          Thread.new do
            begin
              challenge.respond("one", "two")
            rescue ArgumentError
              challenge.respond("just-one")
            end
          end
        end
        reset_subject(keyboard_interactive_handler: handler)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "",
                   :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 1, packet2.read_long
            assert_equal "just-one", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
        assert challenge_ref.expired?
      end

      def test_structured_handler_expires_challenge_on_failure
        received = []
        handler = lambda do |challenge|
          received << challenge
          Thread.new { challenge.respond("the-password") }
        end
        reset_subject(non_interactive: true, keyboard_interactive_handler: handler)

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "",
                   :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            t2.return(USERAUTH_FAILURE, :string, "publickey")
          end
        end

        assert_raises Net::SSH::Authentication::DisallowedMethod do
          subject.authenticate("ssh-connection", "jamis", nil)
        end
        assert received.first.expired?
      end

      def test_structured_handler_does_not_log_answers
        log_io = StringIO.new
        logger = Logger.new(log_io)
        logger.level = Logger::DEBUG
        handler = lambda do |challenge|
          Thread.new { challenge.respond("super-secret") }
        end
        reset_session({})
        auth_transport = transport
        auth_session = stub("auth-session", logger: logger, transport: auth_transport)
        auth_session.define_singleton_method(:next_message) { auth_transport.next_message }
        @subject = Net::SSH::Authentication::Methods::KeyboardInteractive.new(
          auth_session, keyboard_interactive_handler: handler
        )

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "",
                   :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
        assert_match(/keyboard-interactive/, log_io.string)
        refute_match(/super-secret/, log_io.string)
      end

      private

      def subject(options = {})
        @subject ||= Net::SSH::Authentication::Methods::KeyboardInteractive.new(session(options), options)
      end

      def reset_subject(options)
        @subject = nil
        reset_session(options)
        subject(options)
      end
    end
  end
end
