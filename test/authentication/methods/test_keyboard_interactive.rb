require_relative '../../common'
require 'logger'
require 'net/ssh/authentication/session'
require 'net/ssh/authentication/methods/keyboard_interactive'
require_relative 'common'

module Authentication
  module Methods
    class TestKeyboardInteractive < NetSSHTest
      include Common

      USERAUTH_INFO_REQUEST  = 60
      USERAUTH_INFO_RESPONSE = 61

      # A MockTransport whose next_message waits (with a timeout) for server
      # messages, so tests can drive the exchange from another thread, e.g.
      # to submit challenge answers after authenticate has started.
      class BlockingMockTransport < MockTransport
        def next_message
          deadline = Time.now + 5
          loop do
            message = poll_message
            return message if message
            raise "expected a message from the server but nothing was ready to send" if Time.now >= deadline

            sleep 0.01
          end
        end
      end

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

      def test_authenticate_with_challenge_handler_should_support_multiple_rounds
        challenges = Queue.new
        reset_subject(keyboard_interactive_challenge_handler: ->(challenge) { challenges << challenge })

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST,
                   :string, "password round", :string, "enter your credentials", :string, "en",
                   :long, 2, :string, "Name:", :bool, true, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 2, packet2.read_long
            assert_equal "jamis", packet2.read_string
            assert_equal "s3cret", packet2.read_string
            t2.return(USERAUTH_INFO_REQUEST,
                      :string, "otp round", :string, "", :string, "",
                      :long, 1, :string, "One-time code:", :bool, false)
            t2.expect do |t3, packet3|
              assert_equal USERAUTH_INFO_RESPONSE, packet3.type
              assert_equal 1, packet3.read_long
              assert_equal "123456", packet3.read_string
              t3.return(USERAUTH_SUCCESS)
            end
          end
        end

        auth_thread = Thread.new { subject.authenticate("ssh-connection", "jamis") }

        first = challenges.pop
        assert_equal "password round", first.name
        assert_equal "enter your credentials", first.instruction
        assert_equal "en", first.language
        assert_equal 2, first.prompts.length
        assert_equal "Name:", first.prompts[0].text
        assert first.prompts[0].echo?
        assert_equal "Password:", first.prompts[1].text
        refute first.prompts[1].echo?
        assert first.pending?
        assert first.submit(%w[jamis s3cret])

        second = challenges.pop
        assert_equal "otp round", second.name
        assert_equal 1, second.prompts.length

        # the first round is over: its answers must not reach the connection
        refute first.submit(%w[too late])
        refute first.pending?

        assert second.submit(["123456"])

        auth_thread.join(5)
        refute auth_thread.alive?, "authentication did not finish in time"
        assert_equal true, auth_thread.value
        assert second.submitted?
      end

      def test_authenticate_with_challenge_handler_should_handle_empty_challenge
        challenges = Queue.new
        reset_subject(keyboard_interactive_challenge_handler: ->(challenge) { challenges << challenge })

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "banner", :string, "no input needed", :string, "en", :long, 0)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 0, packet2.read_long
            t2.return(USERAUTH_SUCCESS)
          end
        end

        auth_thread = Thread.new { subject.authenticate("ssh-connection", "jamis") }

        challenge = challenges.pop
        assert_equal "banner", challenge.name
        assert_equal "no input needed", challenge.instruction
        assert_equal "en", challenge.language
        assert_equal 0, challenge.prompts.length

        # the answer count must match the prompt count
        refute challenge.submit(["unexpected"])
        assert challenge.pending?

        assert challenge.submit([])

        auth_thread.join(5)
        refute auth_thread.alive?, "authentication did not finish in time"
        assert_equal true, auth_thread.value
        assert challenge.submitted?
      end

      def test_authenticate_with_challenge_handler_should_abort_when_challenge_is_cancelled
        challenges = Queue.new
        reset_subject(keyboard_interactive_challenge_handler: ->(challenge) { challenges << challenge })

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 1, :string, "Password:", :bool, false)
        end

        auth_thread = Thread.new { subject.authenticate("ssh-connection", "jamis") }
        auth_thread.report_on_exception = false

        challenge = challenges.pop
        assert challenge.cancel
        assert challenge.cancelled?

        # a cancelled challenge must not write to the connection
        refute challenge.submit(["s3cret"])

        # the server closes the exchange without receiving a response
        transport.return(USERAUTH_FAILURE, :string, "keyboard-interactive")

        # Thread#join re-raises the thread's exception (Ruby >= 4.0)
        assert_raises(Net::SSH::Authentication::Cancelled) { auth_thread.join(5) }
      end

      def test_unsubmitted_challenge_should_expire_when_a_new_challenge_arrives
        challenges = Queue.new
        reset_subject(keyboard_interactive_challenge_handler: ->(challenge) { challenges << challenge })

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "first", :string, "", :string, "", :long, 1, :string, "Password:", :bool, false)
          t.return(USERAUTH_INFO_REQUEST, :string, "second", :string, "", :string, "", :long, 1, :string, "One-time code:", :bool, false)
          t.return(USERAUTH_SUCCESS)
        end

        assert subject.authenticate("ssh-connection", "jamis")

        first = challenges.pop
        second = challenges.pop
        assert first.expired?
        assert second.expired?

        # stale rounds must not write to the connection
        refute first.submit(["s3cret"])
        refute second.submit(["123456"])
      end

      def test_unsubmitted_challenge_should_expire_when_authentication_succeeds
        challenges = Queue.new
        reset_subject(keyboard_interactive_challenge_handler: ->(challenge) { challenges << challenge })

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 0)
          t.return(USERAUTH_SUCCESS)
        end

        assert subject.authenticate("ssh-connection", "jamis")

        challenge = challenges.pop
        assert challenge.expired?
        refute challenge.submit([])
      end

      def test_unsubmitted_challenge_should_expire_when_authentication_fails
        challenges = Queue.new
        reset_subject(non_interactive: true, keyboard_interactive_challenge_handler: ->(challenge) { challenges << challenge })

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 1, :string, "Password:", :bool, false)
          t.return(USERAUTH_FAILURE, :string, "keyboard-interactive")
        end

        assert_equal false, subject.authenticate("ssh-connection", "jamis")

        challenge = challenges.pop
        assert challenge.expired?
        refute challenge.submit(["s3cret"])
      end

      def test_challenge_answers_should_not_be_logged
        log = StringIO.new
        logger = Logger.new(log)
        logger.level = Logger::DEBUG

        reset_subject(keyboard_interactive_challenge_handler: ->(challenge) { challenge.submit(["s3cret-password"]) })
        subject.logger = logger

        transport.expect do |t, packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2, packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 1, packet2.read_long
            assert_equal "s3cret-password", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis")
        assert_includes log.string, "keyboard-interactive"
        refute_includes log.string, "s3cret-password"
      end

      private

      def transport(options = {})
        @transport ||= BlockingMockTransport.new(options.merge(socket: socket))
      end

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
