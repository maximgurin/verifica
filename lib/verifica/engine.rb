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

    def authorized?(principal, resource, operation, **rest)
    end

    private

    def index_resources(resource_configs)
      resource_configs.each_with_object({}) do |config, by_type|
        if by_type.key?(config.resource_type)
          # TODO: Use own exception
          raise ArgumentError, "Resource registered multiple times, hidden bug?"
        end
        by_type[res.type] = res
      end
    end
  end
end
