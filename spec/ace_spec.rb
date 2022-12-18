# frozen_string_literal: true

RSpec.describe Verifica::Ace do
  let(:ace) { Verifica::Ace.new("root", "read", true) }

  it "should be deep frozen after creation" do
    expect(ace).to be_frozen
    expect(ace.sid).to be_frozen
    expect(ace.action).to be_frozen
  end

  it "should be equal to Ace with same props" do
    same_ace = Verifica::Ace.new("root", :read, true)

    expect(ace).to eql(same_ace)
    expect(ace).to be == same_ace
    expect(ace.hash).to be == same_ace.hash
  end

  it "should return new hash on each #to_h call" do
    first_h = ace.to_h
    second_h = ace.to_h

    expect(first_h).to be == { sid: "root", action: :read, allow: true }
    expect(first_h).to eql(second_h)
    expect(first_h).not_to be second_h
  end

  [
    Verifica::Ace.new("user", :read, true),
    Verifica::Ace.new("root", :write, true),
    Verifica::Ace.new("root", :read, false),
    Verifica::Ace.new("anon", :read, true),
  ].each do |different_ace|
    it "should not be equal to Ace with different props" do
      expect(ace).not_to eql(different_ace)
      expect(ace).not_to be == different_ace
      expect(ace.hash).not_to be == different_ace.hash
    end
  end
end
