# frozen_string_literal: true

module Verifica
  # Security Identifier (SID)
  #
  # Typically SID is an immutable string (you could use other objects too, string just makes it easier to understand)
  # which describes certain fact about a security subject
  # (current user, external service with given API key and scope of permissions, etc.).
  # Each subject has a list of SIDs associated with it.
  # For example, SIDs of a superuser may look like: +["root"]+,
  # and SIDs of a regular user with ID +123+ may look like: +["authenticated", "user:123"]+.
  #
  # Essentially SIDs act as a link between the security subject and Access Control List for each resource in your system.
  #
  # @note This is an optional, convenience module. It adds methods that represent SIDs common for many web applications
  #   so you'll spend less time inventing your own convention. But you are free to use any other convention for SIDs.
  #
  # @example
  #   class User
  #     include Verifica::Sid
  #
  #     def id
  #       # ...
  #     end
  #
  #     def superuser?
  #       # ...
  #     end
  #
  #     def org_id
  #       # ...
  #     end
  #
  #     def subject_sids(**)
  #       if superuser?
  #         [root_sid]
  #       else
  #         [authenticated_sid, user_sid(id), organization_sid(org_id)]
  #       end
  #     end
  #   end
  #
  # @see Acl
  module Sid
    ANONYMOUS_SID = "anonymous"
    AUTHENTICATED_SID = "authenticated"
    ROOT_SID = "root"
    private_constant :ANONYMOUS_SID, :AUTHENTICATED_SID, :ROOT_SID

    # Security Identifier of the anonymous subject. Essentially this is a public SID.
    # Use it when certain resources need to be available to anyone.
    #
    # @example
    #   class PostAclProvider
    #     include Verifica::Sid
    #
    #     def call(post, **)
    #       Verifica::Acl.build do |acl|
    #         if post.public?
    #           acl.allow anonymous_sid, [:read]
    #         end
    #
    #         # ...
    #       end
    #     end
    #   end
    #
    # @return [String]
    #
    # @api public
    def anonymous_sid
      ANONYMOUS_SID
    end

    # Security Identifier of any authenticated subject (current user, external service, etc.).
    #
    # @example
    #   class PostAclProvider
    #     include Verifica::Sid
    #
    #     def call(post)
    #       Verifica::Acl.build do |acl|
    #         if post.public?
    #           acl.allow authenticated_sid, [:read, :comment]
    #         end
    #
    #         # ...
    #       end
    #     end
    #   end
    #
    # @return [String]
    #
    # @api public
    def authenticated_sid
      AUTHENTICATED_SID
    end

    # Security Identifier of the superuser. The name is taken from Unix terminology as it provides a clear separation
    # between true admins and semi-admins common in web applications (e.g. organization admin, chat room admin, etc.).
    # Typically you allow all actions for this SID on all resources.
    #
    # @example
    #   class PostAclProvider
    #     include Verifica::Sid
    #
    #     ALL_ACTIONS = [:read, :write, :delete, :comment]
    #     ROOT_ACL = Acl.build { |acl| acl.allow root_sid, ALL_ACTIONS }
    #
    #     def call(post, **)
    #       ROOT_ACL.build do |acl|
    #         if post.public?
    #           acl.allow authenticated_sid, [:read, :comment]
    #         end
    #
    #         # ...
    #       end
    #     end
    #   end
    #
    # @return [String]
    #
    # @api public
    def root_sid
      ROOT_SID
    end

    # Security Identifier of the regular user with given +user_id+.
    #
    # @note An argument can't be +nil+ for safety reasons.
    #   +nil+ can cause unpredictable consequences like two separate users sharing the same SID and access rights
    #
    # @example
    #   class PostAclProvider
    #     include Verifica::Sid
    #
    #     def call(post, **)
    #       Verifica::Acl.build do |acl|
    #         acl.allow user_sid(post.author_id), [:read, :comment, :write, :delete]
    #
    #         # ...
    #       end
    #     end
    #   end
    #
    # @return [String]
    #
    # @api public
    def user_sid(user_id)
      if user_id.nil?
        raise ArgumentError, "Nil 'user_id' is unsafe. Use empty string if you absolutely need this behavior"
      end

      "user:#{user_id}".freeze
    end

    # Security Identifier of the subject with given +role_id+.
    #
    # @note (see #user_sid)
    #
    # @example
    #   class PostAclProvider
    #     include Verifica::Sid
    #
    #     def call(post, **)
    #       Verifica::Acl.build do |acl|
    #         acl.allow role_sid("moderator"), [:read, :comment, :delete]
    #
    #         # ...
    #       end
    #     end
    #   end
    #
    # @return [String]
    #
    # @api public
    def role_sid(role_id)
      if role_id.nil?
        raise ArgumentError, "Nil 'role_id' is unsafe. Use empty string if you absolutely need this behavior"
      end

      "role:#{role_id}".freeze
    end

    # Security Identifier of the subject who is a member of the organization with given +organization_id+
    #
    # @note (see #user_sid)
    #
    # @example
    #   class PostAclProvider
    #     include Verifica::Sid
    #
    #     def call(post, **)
    #       Verifica::Acl.build do |acl|
    #         if post.internal?
    #           acl.allow organization_sid(post.organization_id), [:read, :comment]
    #         end
    #
    #         # ...
    #       end
    #     end
    #   end
    #
    # @return [String]
    #
    # @api public
    def organization_sid(organization_id)
      if organization_id.nil?
        raise ArgumentError, "Nil 'organization_id' is unsafe. Use empty string if you absolutely need this behavior"
      end

      "org:#{organization_id}".freeze
    end

    # Security Identifier of the subject who is a member of the group with given +group_id+
    #
    # @note (see #user_sid)
    #
    # @example
    #   class PostAclProvider
    #     include Verifica::Sid
    #
    #     def call(post, **)
    #       Verifica::Acl.build do |acl|
    #         post.editor_groups.each do |group_id|
    #           acl.allow group_sid(group_id), [:edit, :delete]
    #         end
    #
    #         # ...
    #       end
    #     end
    #   end
    #
    # @return [String]
    #
    # @api public
    def group_sid(group_id)
      if group_id.nil?
        raise ArgumentError, "Nil 'group_id' is unsafe. Use empty string if you absolutely need this behavior"
      end

      "group:#{group_id}".freeze
    end

    # Security Identifier of the subject whose country is the country with given +country_id+
    #
    # @note (see #user_sid)
    #
    # @example
    #   class PostAclProvider
    #     include Verifica::Sid
    #
    #     def call(post, **)
    #       Verifica::Acl.build do |acl|
    #         acl.allow authenticated_sid, [:read, :comment]
    #         post.banned_countries.each do |country_id|
    #           acl.deny country_sid(country_id), [:read, :comment]
    #         end
    #
    #         # ...
    #       end
    #     end
    #   end
    #
    # @return [String]
    #
    # @api public
    def country_sid(country_id)
      if country_id.nil?
        raise ArgumentError, "Nil 'country_id' is unsafe. Use empty string if you absolutely need this behavior"
      end

      "country:#{country_id}".freeze
    end
  end
end
