module Verifica
  class Engine
    def initialize(resource_configs)
      @resources = index_resources(resource_configs).freeze
      freeze
    end

    def resource_config(resource_type)
      config = @resources[resource_type.to_sym]
      if config.nil?
        # TODO: use own exception
        raise ArgumentError, "Unknown resource type, hidden bug?"
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
        # TODO: Use own exception
        raise ArgumentError, "Resource acl_provider should respond to call and return Verifica::Acl instance"
      end

      acl
    end

    def authorize(subject, resource, action, **context)
      result = authorization_result(subject, resource, action, **context)
      if result.failure?
        # TODO: Write detailed message
        raise UnauthorizedError
      end

      result
    end

    def authorized?(subject, resource, action, **context)
      authorization_result(subject, resource, action, **context).success?
    end

    private def index_resources(resource_configs)
      resource_configs.each_with_object({}) do |config, by_type|
        if by_type.key?(config.resource_type)
          # TODO: Use own exception
          raise ArgumentError, "Resource registered multiple times, hidden bug?"
        end

        by_type[config.resource_type] = config
      end
    end

    private def config_by_resource(resource)
      if resource.nil?
        # TODO: Use own exception
        raise ArgumentError, "Resource should not be nil"
      end

      type = resource.resource_type
      if type.nil?
        # TODO: Use own exception
        raise ArgumentError, "Resource should respond to resource_type call and return not nil type"
      end

      resource_config(type)
    end

    private def authorization_result(subject, resource, action, **context)
      acl = resource_acl(resource, **context)

      action = action.to_sym
      possible_actions = config_by_resource(resource).possible_actions
      unless possible_actions.include?(action)
        # TODO: Use own exception
        raise ArgumentError, "Action is not registered as possible for this resource"
      end

      AuthorizationResult.new(subject, resource, action, acl, **context)
    end
  end
end
