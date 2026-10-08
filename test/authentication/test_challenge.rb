require_relative '../common'
require 'net/ssh/authentication/challenge'

module Authentication
  class TestKeyboardInteractiveChallenge < NetSSHTest
    Challenge = Net::SSH::Authentication::KeyboardInteractiveChallenge
    ChallengeExpired = Net::SSH::Authentication::ChallengeExpired
    ChallengeCanceled = Net::SSH::Authentication::ChallengeCanceled

    def challenge(prompts = nil)
      prompts ||= [Challenge::Prompt.new('Password:', false),
                   Challenge::Prompt.new('Display:', true)]
      Challenge.new(1, 'login', 'please authenticate', 'en-US', prompts)
    end

    def test_keeps_name_instruction_language_and_echo_flags
      item = challenge
      assert_equal 1, item.round
      assert_equal 'login', item.name
      assert_equal 'please authenticate', item.instruction
      assert_equal 'en-US', item.language
      assert_equal ['Password:', 'Display:'], item.prompts.map(&:text)
      assert_equal [false, true], item.prompts.map(&:echo?)
      assert item.pending?
    end

    def test_respond_delivers_answers_in_order
      item = challenge
      answered = nil
      thread = Thread.new { answered = item.take_answers }
      assert item.respond('secret', 'shown')
      thread.join
      assert_equal ['secret', 'shown'], answered
      refute item.pending?
    end

    def test_respond_accepts_a_flat_array
      item = challenge
      thread = Thread.new { item.take_answers }
      assert item.respond(%w[secret shown])
      thread.join
    end

    def test_respond_rejects_wrong_answer_count_and_keeps_pending
      item = challenge
      err = assert_raises(ArgumentError) { item.respond('only-one') }
      assert_match(/expected 2 answer/, err.message)
      assert item.pending?

      assert item.respond('a', 'b')
    end

    def test_cancel_unblocks_with_canceled
      item = challenge
      thread = Thread.new do
        item.take_answers
      rescue ChallengeCanceled
        :canceled
      end
      assert item.cancel
      assert_equal :canceled, thread.join.value
      assert item.canceled?
    end

    def test_answers_after_cancel_are_rejected
      item = challenge
      item.cancel
      assert_raises(ChallengeExpired) { item.respond('secret', 'shown') }
    end

    def test_expire_rejects_late_answers
      item = challenge
      assert item.expire
      assert item.expired?
      assert_raises(ChallengeExpired) { item.respond('secret', 'shown') }
    end

    def test_respond_after_answer_is_rejected
      item = challenge
      item.respond('secret', 'shown')
      assert_raises(ChallengeExpired) { item.respond('other', 'answers') }
    end

    def test_inspect_and_to_s_do_not_leak_answers
      item = challenge
      item.respond('super-secret', 'visible')
      refute_match(/super-secret/, item.inspect)
      refute_match(/super-secret/, item.to_s)
      assert_match(/Password:/, item.inspect)
    end
  end
end
