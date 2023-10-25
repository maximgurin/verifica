# frozen_string_literal: true

RSpec.describe Verifica::Ace do
  subject(:ace) { described_class.new("root", "read", true) }

  it "is deep frozen after creation" do
    expect(Ractor.shareable?(ace)).to be true
  end

  it "returns correct #allow? #deny?" do
    expect(ace).to be_allow
    expect(ace).not_to be_deny
  end

  it "#to_s" do
    expect(ace.to_s).to eq '{:sid=>"root", :action=>:read, :allow=>true}'
  end

  it "is equal to Ace with same props" do
    same_ace = described_class.new("root", :read, true)

    expect(ace).to eql(same_ace)
    expect(ace).to eq same_ace
    expect(ace.hash).to eq same_ace.hash
  end

  it "returns new hash on each #to_h call" do
    first_h = ace.to_h
    second_h = ace.to_h

    expect(first_h).to eq({sid: "root", action: :read, allow: true})
    expect(first_h).to eql(second_h)
    expect(first_h).not_to be second_h
  end

  [
    described_class.new("user", :read, true),
    described_class.new("root", :write, true),
    described_class.new("root", :read, false),
    described_class.new("anon", :read, true)
  ].each do |different_ace|
    it "is not equal to Ace with different props" do
      expect(ace).not_to eql(different_ace)
      expect(ace).not_to eq different_ace
      expect(ace.hash).not_to eq different_ace.hash
    end
  end
end
