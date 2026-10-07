require 'common'
require 'ostruct'
require 'net/ssh/service/forward'

module Service
  class TestForward < NetSSHTest
    def setup
      @hostkey = OpenSSL::PKey::RSA.new(512)
      @session = stub("session", logger: nil)
      @session.stubs(:on_open_channel)
      @session.stubs(:options).returns({})
      @session.stubs(:transport).returns(stub("transport", algorithms: algorithms))
      @forward = Net::SSH::Service::Forward.new(@session)
    end

    def test_forwarded_agent_is_bound_to_session_with_forwarding_flag
      agent = mock("agent")
      agent.expects(:bind_session).with("initial-H", @hostkey, "initial-sig", forwarding: true).returns(:bound)

      bind(agent)
    end

    def test_forwarded_agent_bind_is_skipped_when_session_bind_is_false
      @session.stubs(:options).returns(session_bind: false)
      agent = mock("agent")
      agent.expects(:bind_session).never

      bind(agent)
    end

    def test_forwarded_agent_continues_unbound_when_bind_is_refused_and_fallback_allowed
      agent = mock("agent")
      agent.expects(:bind_session).returns(:refused)

      bind(agent)
    end

    def test_forwarded_agent_continues_unbound_when_extension_is_unsupported
      agent = mock("agent")
      agent.expects(:bind_session).returns(:unsupported)

      bind(agent)
    end

    def test_forwarded_agent_channel_is_refused_when_bind_is_refused_and_binding_required
      @session.stubs(:options).returns(session_bind: :required)
      agent = mock("agent")
      agent.expects(:bind_session).returns(:refused)

      error = assert_raises(Net::SSH::ChannelOpenFailed) { bind(agent) }
      assert_match(/refused/, error.message)
    end

    def test_forwarded_agent_channel_is_refused_when_extension_is_unsupported_and_binding_required
      @session.stubs(:options).returns(session_bind: :required)
      agent = mock("agent")
      agent.expects(:bind_session).returns(:unsupported)

      error = assert_raises(Net::SSH::ChannelOpenFailed) { bind(agent) }
      assert_match(/does not support/, error.message)
    end

    private

    def algorithms
      OpenStruct.new(session_id: "initial-H",
                     initial_hostkey: @hostkey,
                     initial_hostkey_signature: "initial-sig")
    end

    def bind(agent)
      @forward.send(:bind_forwarded_agent, @session, agent)
    end
  end
end
