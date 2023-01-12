# frozen_string_literal: true

module Verifica
  # @api private
  def self.subject_sids(subject, **context)
    if subject.nil?
      raise Error, "Subject should not be nil"
    end

    sids = subject.subject_sids(**context)
    unless sids.is_a?(Array) || sids.is_a?(Set)
      raise Error, "Expected subject to respond to #subject_sids with Array or Set of SIDs but got '#{sids.class}'"
    end

    sids
  end

  class Authorizer
    # @note Use {Verifica.authorizer} instead of this constructor directly
    #
    # @api public
    def initialize(resource_configs)
      @resources = index_resources(resource_configs).freeze
      freeze
    end

    # Checks the authorization of a subject to perform an action on a resource
    #
    # * The +subject+ is asked for its Security Identifiers (SIDs) by +subject.subject_sids+
    # * The +resource+ is asked for its type by +resource.resource_type+
    # * ACL provider registered for this resource type is asked for {Acl} by +#call(resource, **context)+
    # * ACL is checked whether the +action+ is allowed for the subject SIDs
    #
    # @example
    #   def show
    #     post = Post.find(params[:id])
    #     authorizer.authorize(current_user, post, :read)
    #
    #     render json: post
    #   end
    #
    # @param subject [Object] subject of the authorization (e.g. current user, external service)
    # @param resource [Object] resource to authorize for, should respond to +#resource_type+
    # @param action [Symbol, String] action that +subject+ attempts to perform on the +resource+
    # @param context [Hash] arbitrary keyword arguments to forward to +subject.subject_sids+ and +acl_provider.call+
    #
    # @return [AuthorizationResult] authorization result with all details if authorization is successful
    # @raise [AuthorizationError] if +subject+ isn't authorized to perform +action+ on the given +resource+
    # @raise [Error] if +resource.resource_type+ isn't registered in +self+
    #
    # @see Acl#action_allowed? How ACL is checked whether the action is allowed
    # @see Configuration#register_resource
    #
    # @api public
    def authorize(subject, resource, action, **context)
      result = authorization_result(subject, resource, action, **context)
      raise AuthorizationError, result if result.failure?

      result
    end

    # The same as {#authorize} but returns true/false instead of rising an exception
    #
    # @return [Boolean] true if +action+ on +resource+ is authorized for +subject+
    # @raise [Error] if +resource.resource_type+ isn't registered in +self+
    #
    # @api public
    def authorized?(subject, resource, action, **context)
      authorization_result(subject, resource, action, **context).success?
    end

    # @param subject [Object] subject of the authorization (e.g. current user, external service)
    # @param resource [Object] resource to get allowed actions for, should respond to +#resource_type+
    # @param **context (see #authorize)
    #
    # @return [Array<Symbol>] array of actions allowed for +subject+ or empty array if none
    # @raise [Error] if +resource.resource_type+ isn't registered in +self+
    #
    # @see Configuration#register_resource
    # @see Acl#allowed_actions
    #
    # @api public
    def allowed_actions(subject, resource, **context)
      acl = resource_acl(resource, **context)
      sids = Verifica.subject_sids(subject)
      acl.allowed_actions(sids)
    end

    # @param resource_type [Symbol, String] type of the resource
    #
    # @return [ResourceConfiguration] configuration for +resource_type+
    # @raise [Error] if +resource_type+ isn't registered in +self+
    #
    # @see resource_type?
    # @see Configuration#register_resource
    #
    # @api public
    def resource_config(resource_type)
      resource_type = resource_type.to_sym
      config = @resources[resource_type]
      if config.nil?
        raise Error, "Unknown resource '#{resource_type}'. Did you forget to register this resource type?"
      end

      config
    end

    # @param resource_type (see #resource_config)
    #
    # @return [Boolean] true if +resource_type+ is registered in +self+
    #
    # @see Configuration#register_resource
    #
    # @api public
    def resource_type?(resource_type)
      @resources.key?(resource_type.to_sym)
    end

    # @param resource [Object] resource to get ACL for, should respond to +#resource_type+
    # @param context [Hash] arbitrary keyword arguments to forward to +acl_provider.call+
    #
    # @return [Acl] Access Control List for +resource+
    # @raise [Error] if +resource_type+ isn't registered in +self+
    # @raise [Error] if ACL provider for this resource type doesn't respond to +#call(resource, **)+ with {Acl} object
    #
    # @see Configuration#register_resource
    #
    # @api public
    def resource_acl(resource, **context)
      config = config_by_resource(resource)
      acl = config.acl_provider.call(resource, **context)
      unless acl.is_a?(Verifica::Acl)
        type = resource.resource_type
        raise Error, "'#{type}' resource acl_provider should respond to #call with Acl object but got '#{acl.class}'"
      end

      acl
    end

    private def index_resources(resource_configs)
      resource_configs.each_with_object({}) do |config, by_type|
        type = config.resource_type
        if by_type.key?(type)
          raise Error, "'#{type}' resource registered multiple times. Probably code copy-paste and a bug?"
        end

        by_type[type] = config
      end
    end

    private def config_by_resource(resource)
      if resource.nil?
        raise Error, "Resource should not be nil"
      end

      type = resource.resource_type
      if type.nil?
        raise Error, "Resource should respond to #resource_type with non-nil type"
      end

      resource_config(type)
    end

    private def authorization_result(subject, resource, action, **context)
      action = action.to_sym
      possible_actions = config_by_resource(resource).possible_actions
      unless possible_actions.include?(action)
        raise Error, "'#{action}' action is not registered as possible for '#{resource.resource_type}' resource"
      end

      acl = resource_acl(resource, **context)
      AuthorizationResult.new(subject, resource, action, acl, **context)
    end
  end
end
