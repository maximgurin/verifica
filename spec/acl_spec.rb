# frozen_string_literal: true

RSpec.describe Verifica::Acl do
  let(:sid) { Class.new { extend Verifica::Sid } }
  let(:owner_user_id) { 777 }
  let(:other_user_id) { 321 }
  let(:banned_organization_id) { 666 }
  let(:moderator_role_id) { "moderator" }
  let(:acl) do
    Verifica::Acl.build do |acl|
      acl.allow sid.anonymous, %i[read]
      acl.allow sid.authenticated, %i[read comment]
      acl.allow sid.role(moderator_role_id), %i[read unpublish]
      acl.allow sid.user(owner_user_id), %w[read write delete comment]
      acl.deny sid.organization(banned_organization_id), %w[read comment]
    end
  end

  it "should be deep frozen after creation" do
    aces = acl.to_a

    expect(acl).to be_frozen
    expect(aces).to be_frozen
    expect(aces).to all(be_frozen)
  end

  it "should allow action if any SID is allowed and no SIDs are denied" do
    sids = [sid.authenticated, sid.user(other_user_id)]

    expect(acl.action_allowed?(:read, sids)).to be true
    expect(acl.action_denied?(:read, sids)).to be false
  end

  it "should allow action if all SIDs are allowed no SIDs are denied" do
    sids = [sid.authenticated, sid.user(owner_user_id)]

    expect(acl.action_allowed?(:comment, sids)).to be true
  end

  it "should deny action if any SID is denied" do
    sids = [sid.authenticated, sid.organization(banned_organization_id)]

    expect(acl.action_allowed?(:read, sids)).to be false
  end

  it "should deny action if no SIDs are allowed" do
    sids = [sid.anonymous, "some random SID"]

    expect(acl.action_allowed?(:unpublish, sids)).to be false
  end

  it "should return all allowed SIDs for action" do
    sids = acl.allowed_sids(:comment)

    expect(acl.allowed_sids(:comment)).to contain_exactly(sid.user(owner_user_id), sid.authenticated)
    expect(sids).to be_frozen
    expect(sids).to all(be_frozen)
  end

  it "should return all denied SIDs for action" do
    sids = acl.denied_sids(:read)

    expect(sids).to contain_exactly(sid.organization(banned_organization_id))
    expect(sids).to be_frozen
    expect(sids).to all(be_frozen)
  end

  it "should return all allowed actions for set of SIDs" do
    sids = Set.new([sid.authenticated, sid.role(moderator_role_id)])

    expect(acl.allowed_actions(sids)).to contain_exactly(:unpublish, :comment, :read)
  end

  it "should return new set on each allowed_actions call" do
    sids = Set.new([sid.authenticated, sid.role(moderator_role_id)])

    first_actions = acl.allowed_actions(sids)
    second_actions = acl.allowed_actions(sids)

    expect(first_actions).to eql(second_actions)
    expect(first_actions).not_to be second_actions
  end

  it "should return no allowed actions for denied SIDs" do
    sids = Set.new([sid.authenticated, sid.organization(banned_organization_id)])

    expect(acl.allowed_actions(sids)).to be_empty
  end

  it "should remove duplicate entries" do
    three_actions_acl = Verifica::Acl.build do |acl|
      acl.allow sid.root, %i[read write delete]
      acl.allow sid.root, %i[read write]
      acl.allow sid.root, %i[delete read]
    end

    expect(three_actions_acl).not_to be_empty
    expect(three_actions_acl.size).to eql(3)
    expect(three_actions_acl.length).to eql(3)
  end

  it "should be empty if aces are empty" do
    empty_acl = Verifica::Acl.new([])

    expect(empty_acl).to be_empty
  end

  it "should convert string action to symbol" do
    sids = [sid.authenticated, sid.user(other_user_id)]

    expect(acl.action_allowed?("read", sids)).to be true
    expect(acl.action_denied?("read", sids)).to be false
  end

  it "should not allow anything for empty SIDs" do
    sids = []

    expect(acl.allowed_actions(sids)).to be_empty
    expect(acl.action_denied?(:read, sids)).to be true
  end

  context "unknown action" do
    it "should not be allowed" do
      sids = [sid.authenticated, sid.user(other_user_id)]

      expect(acl.action_allowed?(:unknown_action, sids)).to be false
      expect(acl.action_denied?(:unknown_action, sids)).to be true
    end

    it "should not have allowed or denied sids" do
      expect(acl.allowed_sids(:unknown_action)).to be_empty
      expect(acl.denied_sids(:unknown_action)).to be_empty
    end
  end
end
