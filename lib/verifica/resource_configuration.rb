require "set"

module Verifica
  class ResourceConfiguration
    attr_reader :resource_type, :possible_operations, :acl_provider

    def initialize(resource_type, possible_operations, acl_provider)
      @resource_type = resource_type.to_sym
      @possible_operations = operations_set(possible_operations).freeze
      @acl_provider = acl_provider
      freeze
    end

    private

    def operations_set(possible_operations)
      if possible_operations.empty?
        # TODO: Use own exception
        raise ArgumentError, "Empty possible operations for resource, hidden bug?"
      end

      ops_set = possible_operations.map(&:to_sym).to_set
      if ops_set.size < possible_operations.size
        # TODO: Use own exception
        raise ArgumentError, "Duplicate, hidden bug?"
      end
      ops_set
    end
  end
end
