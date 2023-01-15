# frozen_string_literal: true

require_relative "verifica/acl"
require_relative "verifica/authorization_result"
require_relative "verifica/authorizer"
require_relative "verifica/configuration"
require_relative "verifica/errors"
require_relative "verifica/sid"
require_relative "verifica/version"

# Verifica is Ruby's most scalable authorization solution ready to handle sophisticated authorization rules.
#
# - Framework and database agnostic
# - Scalable. Start from 10, grow to 10M records in the database while having the same authorization architecture
# - Supports any actor in your application. Traditional +current_user+, external service, API client, you name it
# - No global state. Only local, immutable objects
# - Plain old Ruby, zero dependencies, no magic
#
# Verifica is designed around Access Control List. ACL clearly separates authorization rules definition
# (who can do what for any given resource) and execution (can +current_user+ delete this post?).
#
# @example
#   require 'verifica'
#
#   User = Struct.new(:id, :role, keyword_init: true) do
#     # Verifica expects each security subject to respond to #subject_id, #subject_type, and #subject_sids
#     alias_method :subject_id, :id
#     def subject_type = :user
#
#     def subject_sids(**)
#       role == "root" ? ["root"] : ["authenticated", "user:#{id}"]
#     end
#   end
#
#   Video = Struct.new(:id, :author_id, :public, keyword_init: true) do
#     # Verifica expects each secured resource to respond to #resource_id, and #resource_type
#     alias_method :resource_id, :id
#     def resource_type = :video
#   end
#
#   video_acl_provider = lambda do |video, **|
#     Verifica::Acl.build do |acl|
#       acl.allow "root", [:read, :write, :delete, :comment]
#       acl.allow "user:#{video.author_id}", [:read, :write, :delete, :comment]
#
#       if video.public
#         acl.allow "authenticated", [:read, :comment]
#       end
#     end
#   end
#
#   authorizer = Verifica.authorizer do |config|
#     config.register_resource :video, [:read, :write, :delete, :comment], video_acl_provider
#   end
#
#   public_video = Video.new(id: 1, author_id: 1000, public: true)
#   private_video = Video.new(id: 2, author_id: 1000, public: true)
#
#   superuser = User.new(id: 777, role: "root")
#   video_author = User.new(id: 1000, role: "user")
#   other_user = User.new(id: 2000, role: "user")
#
#   authorizer.authorized?(superuser, private_video, :delete)
#   # true
#
#   authorizer.authorized?(video_author, private_video, :delete)
#   # true
#
#   authorizer.authorized?(other_user, private_video, :read)
#   # false
#
#   authorizer.authorized?(other_user, public_video, :comment)
#   # true
#
#   authorizer.authorize(other_user, public_video, :write)
#   # raises Verifica::AuthorizationError: Authorization FAILURE. Subject 'user' id='2000'. Resource 'video' id='1'. Action 'write'
#
# @api public
module Verifica
  EMPTY_ARRAY = [].freeze
  private_constant :EMPTY_ARRAY

  # Empty, frozen Access Control List. Semantically means that no actions are allowed
  #
  # @api public
  EMPTY_ACL = Verifica::Acl.new(EMPTY_ARRAY).freeze

  # Creates a new {Configuration} and yields it to the given block
  #
  # @example
  #   post_acl_provider = lambda do |post, **|
  #     Verifica::Acl.build do |acl|
  #       acl.allow "root", [:read, :write, :delete, :comment]
  #       acl.allow "user:#{post.author_id}", [:read, :write, :delete, :comment]
  #
  #       if post.public
  #         acl.allow "authenticated", [:read, :comment]
  #       end
  #     end
  #   end
  #
  #   user_acl_provider = lambda do |user, **|
  #     Verifica::Acl.build do |acl|
  #       acl.allow "root", [:read, :write, :delete]
  #       acl.allow "user:#{user.id}", [:read, :write]
  #     end
  #   end
  #
  #   authorizer = Verifica.authorizer do |config|
  #     config.register_resource :post, [:read, :write, :delete, :comment], post_acl_provider
  #     config.register_resource :user, [:read, :write, :delete], user_acl_provider
  #   end
  #
  # @return [Authorizer] a new Authorizer configured by the given block
  #
  # @api public
  def self.authorizer
    config = Configuration.new
    yield config
    Authorizer.new(config.resources)
  end
end
