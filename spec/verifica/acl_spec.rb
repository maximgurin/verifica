# frozen_string_literal: true

RSpec.describe Verifica::Acl do
  subject(:acl) do
    described_class.build do |acl|
      acl.allow sid.anonymous_sid, %i[read]
      acl.allow sid.authenticated_sid, %i[read comment]
      acl.allow sid.role_sid(moderator_role_id), %i[read unpublish]
      acl.allow sid.user_sid(owner_user_id), %w[read write delete comment]
      acl.deny sid.organization_sid(banned_organization_id), %w[read comment bookmark]
    end
  end

  let(:sid) { Class.new { extend Verifica::Sid } }
  let(:owner_user_id) { 777 }
  let(:other_user_id) { 321 }
  let(:banned_organization_id) { 666 }
  let(:moderator_role_id) { "moderator" }

  it "is deep frozen after creation" do
    expect(Ractor.shareable?(acl)).to be true
  end

  it "#to_s" do
    short_acl = described_class.build { _1.allow "root", [:read] }

    expect(short_acl.to_s).to be == '[{:sid=>"root", :action=>:read, :allow=>true}]'
  end

  it "returns new array on each #to_a call" do
    first_a = acl.to_a
    second_a = acl.to_a

    expect(first_a).to eql(second_a)
    expect(first_a).not_to be second_a
  end

  it "allows action if any SID is allowed and no SIDs are denied" do
    sids = [sid.authenticated_sid, sid.user_sid(other_user_id)]

    expect(acl.action_allowed?(:read, sids)).to be true
    expect(acl.action_denied?(:read, sids)).to be false
  end

  it "allows action if all SIDs are allowed no SIDs are denied" do
    sids = [sid.authenticated_sid, sid.user_sid(owner_user_id)]

    expect(acl.action_allowed?(:comment, sids)).to be true
  end

  it "denies action if any SID is denied" do
    sids = [sid.authenticated_sid, sid.organization_sid(banned_organization_id)]

    expect(acl.action_allowed?(:read, sids)).to be false
  end

  it "denies action if no SIDs are allowed" do
    sids = [sid.anonymous_sid, "some random SID"]

    expect(acl.action_allowed?(:unpublish, sids)).to be false
  end

  it "returns all allowed SIDs for action" do
    sids = acl.allowed_sids(:comment)

    expect(sids).to contain_exactly(sid.user_sid(owner_user_id), sid.authenticated_sid)
    expect(sids).to all(be_frozen)
  end

  it "returns all denied SIDs for action" do
    sids = acl.denied_sids(:read)

    expect(sids).to contain_exactly(sid.organization_sid(banned_organization_id))
    expect(sids).to all(be_frozen)
  end

  it "returns all allowed actions for set of SIDs" do
    sids = Set.new([sid.authenticated_sid, sid.role_sid(moderator_role_id)])

    expect(acl.allowed_actions(sids)).to contain_exactly(:unpublish, :comment, :read)
  end

  it "returns new set on each #allowed_actions call" do
    sids = Set.new([sid.authenticated_sid, sid.role_sid(moderator_role_id)])

    first_actions = acl.allowed_actions(sids)
    second_actions = acl.allowed_actions(sids)

    expect(first_actions).to eql(second_actions)
    expect(first_actions).not_to be second_actions
  end

  it "returns no allowed actions for denied SIDs" do
    sids = Set.new([sid.authenticated_sid, sid.organization_sid(banned_organization_id)])

    expect(acl.allowed_actions(sids)).to be_empty
  end

  it "removes duplicate entries" do
    three_actions_acl = described_class.build do |acl|
      acl.allow sid.root_sid, %i[read write delete]
      acl.allow sid.root_sid, %i[read write]
      acl.allow sid.root_sid, %i[delete read]
    end

    expect(three_actions_acl).not_to be_empty
    expect(three_actions_acl.size).to be(3)
    expect(three_actions_acl.length).to be(3)
  end

  it "is empty if ACEs are empty" do
    empty_acl = described_class.new([])

    expect(empty_acl).to be_empty
  end

  it "converts string action to symbol" do
    sids = [sid.authenticated_sid, sid.user_sid(other_user_id)]

    expect(acl.action_allowed?("read", sids)).to be true
    expect(acl.action_denied?("read", sids)).to be false
  end

  it "does not allow anything for empty SIDs" do
    sids = []

    expect(acl.allowed_actions(sids)).to be_empty
    expect(acl.action_denied?(:read, sids)).to be true
  end

  it "is == to ACL with same ACEs regardless of order" do
    first = described_class.build do |acl|
      acl.allow "root", %i[write]
      acl.allow "anonymous", %i[read]
    end
    second = described_class.build do |acl|
      acl.allow "anonymous", %i[read]
      acl.allow "root", %i[write]
    end

    expect(first).to be == second
    expect(first.hash).to be == second.hash
  end

  it "returns new ACL with additional ACEs from builder on #build call" do
    original_acl = described_class.build do |acl|
      acl.allow "root", %i[write]
    end
    new_acl = original_acl.build do |acl|
      acl.allow "anonymous", %i[read]
    end

    expected_original = described_class.build do |acl|
      acl.allow "root", %i[write]
    end
    expected_new = described_class.build do |acl|
      acl.allow "root", %i[write]
      acl.allow "anonymous", %i[read]
    end

    expect(original_acl).to be == expected_original
    expect(new_acl).to be == expected_new
  end

  context "when action is not registered" do
    it "action is not allowed" do
      sids = [sid.authenticated_sid, sid.user_sid(other_user_id)]

      expect(acl.action_allowed?(:unknown_action, sids)).to be false
      expect(acl.action_denied?(:unknown_action, sids)).to be true
    end

    it "has empty allowed or denied sids" do
      expect(acl.allowed_sids(:unknown_action)).to be_empty
      expect(acl.denied_sids(:unknown_action)).to be_empty
    end
  end
end
