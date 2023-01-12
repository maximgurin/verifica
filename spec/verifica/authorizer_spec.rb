# frozen_string_literal: true

require "securerandom"

RSpec.describe Verifica::Authorizer do
  subject(:authorizer) do
    Verifica.authorizer do |config|
      config.register_resource :post, %i[read write comment delete], post_acl_provider
    end
  end

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
    Struct.new(:id, :author_id) do
      alias_method :resource_id, :id

      def resource_type = "post"
    end
  end
  let(:post_acl_provider) do
    lambda do |resource, **|
      Verifica::Acl.build do |acl|
        acl.allow sid.root_sid, %i[read write comment delete]
        acl.allow sid.user_sid(resource.author_id), %i[read write comment delete]
        acl.allow sid.authenticated_sid, %i[read comment]
        acl.allow sid.anonymous_sid, %i[read]
      end
    end
  end
  let(:root_sids) { [sid.root_sid] }

  it "authorizes action if it's allowed in ACL" do
    current_user = user_class.new(SecureRandom.uuid, root_sids)
    post = post_class.new(SecureRandom.uuid, SecureRandom.uuid)

    result = authorizer.authorize(current_user, post, :delete)

    expect(result).to be_success
    expect(result.subject_type).to be == :user
    expect(result.subject_id).to be == current_user.subject_id
    expect(result.resource_type).to be == :post
    expect(result.resource_id).to be == post.resource_id
    expect(result.allowed_actions).to be == %i[read write comment delete]
  end

  it "raises exception if action is not authorized" do
    user_id = SecureRandom.uuid
    current_user = user_class.new(user_id, [sid.authenticated_sid, sid.user_sid(user_id)])
    post = post_class.new(SecureRandom.uuid, SecureRandom.uuid)
    message = "Authorization FAILURE. Subject 'user' id='#{current_user.subject_id}'. Resource 'post' " \
      "id='#{post.resource_id}'. Action 'delete'"

    expect { authorizer.authorize(current_user, post, :delete, scope: :api, type: :internal) }
      .to raise_error(an_instance_of(Verifica::AuthorizationError).and(
        having_attributes(
          message: message,
          explain: /Authorization FAILURE/,
          subject: current_user,
          subject_type: :user,
          subject_id: current_user.subject_id,
          subject_sids: [sid.authenticated_sid, sid.user_sid(user_id)],
          resource: post,
          resource_type: :post,
          resource_id: post.resource_id,
          action: :delete,
          context: {scope: :api, type: :internal},
          acl: authorizer.resource_acl(post)
        )
      ))
  end

  it "returns all allowed actions for given subject" do
    current_user = user_class.new(SecureRandom.uuid, root_sids)
    post = post_class.new(SecureRandom.uuid, SecureRandom.uuid)

    expect(authorizer.allowed_actions(current_user, post)).to be == %i[read write comment delete]
  end

  it "returns true/false in #authorized?" do
    user_id = SecureRandom.uuid
    current_user = user_class.new(user_id, [sid.authenticated_sid, sid.user_sid(user_id)])
    post = post_class.new(SecureRandom.uuid, SecureRandom.uuid)

    expect(authorizer.authorized?(current_user, post, :read)).to be true
    expect(authorizer.authorized?(current_user, post, :delete)).to be false
  end

  it "#resource_type?" do
    expect(authorizer.resource_type?(:post)).to be true
    expect(authorizer.resource_type?("post")).to be true
    expect(authorizer.resource_type?("unknown_type")).to be false
  end

  it "raises exception if action is not registered for resource" do
    current_user = user_class.new(SecureRandom.uuid, root_sids)
    post = post_class.new(SecureRandom.uuid, SecureRandom.uuid)
    unknown_msg = "'unknown_action' action is not registered as possible for 'post' resource"

    expect { authorizer.authorized?(current_user, post, :unknown_action) }
      .to raise_error(an_instance_of(Verifica::Error).and(
        having_attributes(
          message: unknown_msg,
          explain: unknown_msg
        )
      ))
  end

  it "raises exception for invalid or unknown resource" do
    current_user = user_class.new(SecureRandom.uuid, root_sids)
    unknown_type = Class.new do
      def resource_type = :unknown_type
    end.new
    nil_type = Class.new do
      def resource_type = nil
    end.new
    unknown_msg = "Unknown resource 'unknown_type'. Did you forget to register this resource type?"
    nil_type_msg = "Resource should respond to #resource_type with non-nil type"
    nil_res_msg = "Resource should not be nil"

    expect { authorizer.authorized?(current_user, unknown_type, :read) }.to raise_error(Verifica::Error, unknown_msg)
    expect { authorizer.authorized?(current_user, nil_type, :read) }.to raise_error(Verifica::Error, nil_type_msg)
    expect { authorizer.authorized?(current_user, nil, :read) }.to raise_error(Verifica::Error, nil_res_msg)
  end

  it "raises exception for invalid or unknown subject" do
    post = post_class.new(SecureRandom.uuid, SecureRandom.uuid)
    nil_sids = Class.new do
      def subject_id = SecureRandom.uuid

      def subject_type = :user

      def subject_sids = nil
    end.new
    string_sids = Class.new do
      def subject_id = SecureRandom.uuid

      def subject_type = :user

      def subject_sids = "root"
    end.new
    nil_sids_msg = "Expected subject to respond to #subject_sids with Array or Set of SIDs but got 'NilClass'"
    string_sids_msg = "Expected subject to respond to #subject_sids with Array or Set of SIDs but got 'String'"
    nil_subject_msg = "Subject should not be nil"

    expect { authorizer.authorized?(nil_sids, post, :read) }.to raise_error(Verifica::Error, nil_sids_msg)
    expect { authorizer.authorized?(string_sids, post, :read) }.to raise_error(Verifica::Error, string_sids_msg)
    expect { authorizer.authorized?(nil, post, :read) }.to raise_error(Verifica::Error, nil_subject_msg)
  end

  it "raises exception for invalid Acl from provider" do
    provider = instance_double(Proc)
    verifica = Verifica.authorizer do |config|
      config.register_resource :post, %i[read write comment delete], provider
    end
    current_user = user_class.new(SecureRandom.uuid, root_sids)
    post = post_class.new(SecureRandom.uuid, SecureRandom.uuid)

    allow(provider).to receive(:call).and_return(nil)
    msg = "'post' resource acl_provider should respond to #call with Acl object but got 'NilClass'"
    expect { verifica.authorize(current_user, post, :read) }.to raise_error(Verifica::Error, msg)

    allow(provider).to receive(:call).and_return([])
    msg = "'post' resource acl_provider should respond to #call with Acl object but got 'Array'"
    expect { verifica.authorize(current_user, post, :read) }.to raise_error(Verifica::Error, msg)
  end

  it "raises exception for resource registration duplicate" do
    authorizer = lambda do
      Verifica.authorizer do |config|
        config.register_resource :post, %i[read], post_acl_provider
        config.register_resource :post, %i[write], post_acl_provider
      end
    end
    msg = "'post' resource registered multiple times. Probably code copy-paste and a bug?"

    expect { authorizer.call }.to raise_error(Verifica::Error, msg)
  end

  it "forwards arbitrary keyword args to ACL provider and Subject#subject_sids" do
    provider = instance_double(Proc)
    verifica = Verifica.authorizer do |config|
      config.register_resource :post, %i[read write comment delete], provider
    end
    current_user = instance_double(user_class)
    post = instance_double(post_class)
    acl = Verifica::Acl.build { _1.allow sid.root_sid, %i[read write comment delete] }
    kwargs = {scope: "api", type: :internal}

    allow(current_user).to receive(:subject_sids).and_return(root_sids)
    allow(current_user).to receive(:subject_id).and_return(nil)
    allow(current_user).to receive(:subject_type).and_return(nil)
    allow(provider).to receive(:call).and_return(acl)
    allow(post).to receive(:resource_id).and_return(nil)
    allow(post).to receive(:resource_type).and_return(:post)

    verifica.authorize(current_user, post, :read, **kwargs)

    expect(provider).to have_received(:call).with(post, **kwargs)
    expect(current_user).to have_received(:subject_sids).with(**kwargs)
  end
end
