module Verifica
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
    def initialize(resource_configs)
      @resources = index_resources(resource_configs).freeze
      freeze
    end

    def authorize(subject, resource, action, **context)
      result = authorization_result(subject, resource, action, **context)
      if result.failure?
        raise AuthorizationError, result
      end

      result
    end

    def authorized?(subject, resource, action, **context)
      authorization_result(subject, resource, action, **context).success?
    end

    def allowed_actions(subject, resource, **context)
      acl = resource_acl(resource, **context)
      sids = Verifica.subject_sids(subject)
      acl.allowed_actions(sids)
    end

    def resource_config(resource_type)
      resource_type = resource_type.to_sym
      config = @resources[resource_type]
      if config.nil?
        raise Error, "Unknown resource '#{resource_type}'. Did you forget to register this type of resource?"
      end

      config
    end

    def resource_config?(resource_type)
      @resources.key?(resource_type.to_sym)
    end

    def resource_acl(resource, **context)
      config = config_by_resource(resource)
      acl = config.acl_provider.call(resource, **context)
      unless acl.is_a?(Verifica::Acl)
        type = resource.resource_type
        raise Error, "'#{type}' resource acl_provider should respond to #call with Acl instance but got '#{acl.class}'"
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
      acl = resource_acl(resource, **context)

      action = action.to_sym
      possible_actions = config_by_resource(resource).possible_actions
      unless possible_actions.include?(action)
        raise Error, "'#{action}' action is not registered as possible for '#{resource.resource_type}' resource"
      end

      AuthorizationResult.new(subject, resource, action, acl, **context)
    end
  end
end
