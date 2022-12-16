# frozen_string_literal: true

RSpec.describe Verifica::Ace do
  let(:ace) { Verifica::Ace.new("root", "read", true) }

  it "should be deep frozen after creation" do
    expect(ace).to be_frozen
    expect(ace.sid).to be_frozen
    expect(ace.operation).to be_frozen
  end

  it "should be equal to Ace with same props" do
    same_ace = Verifica::Ace.new("root", :read, true)

    expect(ace).to eql(same_ace)
    expect(ace).to be == same_ace
    expect(ace.hash).to be == same_ace.hash
  end

  [
    Verifica::Ace.new("user", :read, true),
    Verifica::Ace.new("root", :write, true),
    Verifica::Ace.new("root", :read, false),
    Verifica::Ace.new("anon", :read, true),
  ].each do |other_ace|
    it "should not be equal to Ace with different props" do
      expect(ace).not_to eql(other_ace)
      expect(ace).not_to be == other_ace
      expect(ace.hash).not_to be == other_ace.hash
    end
  end
end
