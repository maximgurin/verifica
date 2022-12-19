# frozen_string_literal: true

RSpec.describe Verifica::ResourceConfiguration do
  let(:acl_provider) do
    lambda do |_, **|
      Verifica::EMPTY_ACL
    end
  end

  it "should convert resource_type to symbol" do
    config = Verifica::ResourceConfiguration.new("post", %i[read], acl_provider)

    expect(config.resource_type).to eql(:post)
  end

  it "should not accept nil acl_provider" do
    msg = "'post' resource acl_provider should not be nil"

    expect { Verifica::ResourceConfiguration.new(:post, %i[read], nil) }.to raise_error(Verifica::Error, msg)
  end

  it "should not accept empty possible_actions" do
    msg = "Empty possible actions for 'post' resource. Probably a bug?"

    expect { Verifica::ResourceConfiguration.new(:post, Set.new, nil) }.to raise_error(Verifica::Error, msg)
  end

  it "should not accept duplicates in possible_actions" do
    actions = %i[read write delete read hide delete]
    msg = "'[:read, :delete]' possible actions for 'post' resource are specified several times. " \
      "Probably code copy-paste and a bug?"

    expect { Verifica::ResourceConfiguration.new(:post, actions, nil) }.to raise_error(Verifica::Error, msg)
  end
end
