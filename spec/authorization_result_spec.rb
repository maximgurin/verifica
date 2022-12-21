# frozen_string_literal: true

RSpec.describe Verifica::AuthorizationResult do
  let(:sid) { Class.new { extend Verifica::Sid } }
  let(:user_class) do
    Struct.new(:id, :sids) do
      alias_method :subject_id, :id

      def subject_type = :user

      def subject_sids(**)
        sids
      end
    end
  end
  let(:post_class) do
    Struct.new(:id) do
      alias_method :resource_id, :id
      def resource_type = "post"
    end
  end

  it "#explain for successful authorization" do
    current_user = user_class.new(SecureRandom.uuid, [sid.root])
    post = post_class.new(SecureRandom.uuid)
    acl = Verifica::Acl.build { _1.allow sid.root, %i[read write] }
    context = {scope: :api, type: "internal"}

    result = Verifica::AuthorizationResult.new(current_user, post, :read, acl, **context)
    explain = result.explain
    reason = %{Reason: subject SID(s) ["root"] allowed for 'read' action. No SIDs denied among subject SIDs}

    expect(result).to be_success
    expect(explain).to match(/Authorization SUCCESS/)
    expect(explain).to match(/Subject SIDs \(1\)/)
    expect(explain).to match(/Resource ACL \(2\)/)
    expect(explain).to match(Regexp.new(Regexp.escape(context.to_s)))
    expect(explain).to match(Regexp.new(Regexp.escape(reason)))
  end

  it "#explain for empty subject SIDs" do
    current_user = user_class.new(SecureRandom.uuid, [])
    post = post_class.new(SecureRandom.uuid)
    acl = Verifica::Acl.build { _1.allow sid.root, %i[read write] }

    result = Verifica::AuthorizationResult.new(current_user, post, :read, acl)
    explain = result.explain
    reason = "Reason: subject SIDs are empty, no actions allowed for any resource"

    expect(explain).to match(/Authorization FAILURE/)
    expect(explain).to match(/Subject SIDs \(empty\)/)
    expect(explain).to match(Regexp.new(Regexp.escape(reason)))
  end

  it "#explain for empty resource ACL" do
    current_user = user_class.new(SecureRandom.uuid, [sid.root])
    post = post_class.new(SecureRandom.uuid)

    result = Verifica::AuthorizationResult.new(current_user, post, :read, Verifica::EMPTY_ACL)
    explain = result.explain
    reason = %(Reason: resource ACL is empty, no actions allowed for any subject)

    expect(explain).to match(/Authorization FAILURE/)
    expect(explain).to match(/Resource ACL \(empty\)/)
    expect(explain).to match(Regexp.new(Regexp.escape(reason)))
  end

  it "#explain for no allowed SIDs" do
    current_user = user_class.new(SecureRandom.uuid, Set.new([sid.authenticated, sid.anonymous]))
    post = post_class.new(SecureRandom.uuid)
    acl = Verifica::Acl.build { _1.allow sid.root, %i[read write] }

    result = Verifica::AuthorizationResult.new(current_user, post, "read", acl)
    explain = result.explain
    reason = %{Reason: among 2 subject SID(s), none is listed as allowed for 'read' action}

    expect(explain).to match(/Authorization FAILURE/)
    expect(explain).to match(Regexp.new(Regexp.escape(reason)))
  end

  it "#explain for denied SIDs" do
    current_user = user_class.new(SecureRandom.uuid, [sid.authenticated, sid.anonymous])
    post = post_class.new(SecureRandom.uuid)
    acl = Verifica::Acl.build { _1.allow(sid.root, %i[read write]).deny(sid.authenticated, %i[write]) }

    result = Verifica::AuthorizationResult.new(current_user, post, :write, acl)
    explain = result.explain
    reason = %{Reason: subject SID(s) ["authenticated"] denied for 'write' action. } \
      "Denied SIDs always win regardless of allowed SIDs"

    expect(result).to be_failure
    expect(explain).to match(Regexp.new(Regexp.escape(reason)))
  end
end
