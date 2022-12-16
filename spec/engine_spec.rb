# frozen_string_literal: true

require "securerandom"

RSpec.describe Verifica::Engine do
  let(:sid) { Class.new { extend Verifica::Sid } }
  let(:user_struct) do
    Struct.new(:id, :superadmin) do
      include Verifica::Sid
      alias subject_id id

      def subject_type
        :user
      end

      def subject_sids
        if superadmin
          return [root]
        end

        [authenticated, user(id)]
      end
    end
  end
  let(:post_struct) do
    Struct.new(:id, :author_id) do
      alias resource_id id

      def resource_type
        :post
      end
    end
  end
  let(:post_acl_provider) do
    lambda  do |resource, **|
      Verifica::Acl.build do |acl|
        acl.allow sid.root, %i[read write comment delete]
        acl.allow sid.user(resource.author_id), %i[read write comment delete]
        acl.allow sid.authenticated, %i[read comment]
        acl.allow sid.anonymous, %i[read]
      end
    end
  end
  let(:verifica) do
    Verifica.engine do |config|
      config.register_resource :post, %i[read write comment delete], post_acl_provider
    end
  end

  it "should authorize action if it's allowed in ACL" do
    current_user = user_struct.new(SecureRandom.uuid, true)
    post = post_struct.new(SecureRandom.uuid, SecureRandom.uuid)

    result = verifica.authorize(current_user, post, :delete)

    expect(result).to be_success
    expect(result.subject_type).to be == :user
    expect(result.subject_id).to be == current_user.subject_id
    expect(result.resource_type).to be == :post
    expect(result.resource_id).to be == post.resource_id
  end
end
