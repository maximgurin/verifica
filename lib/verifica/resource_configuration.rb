require "set"

module Verifica
  class ResourceConfiguration
    attr_reader :resource_type, :possible_actions, :acl_provider

    def initialize(resource_type, possible_actions, acl_provider)
      @resource_type = resource_type.to_sym
      @possible_actions = action_set(possible_actions).freeze
      @acl_provider = acl_provider
      freeze
    end

    private

    def action_set(possible_actions)
      if possible_actions.empty?
        # TODO: Use own exception
        raise ArgumentError, "Empty possible actions for resource, hidden bug?"
      end

      action_set = possible_actions.map(&:to_sym).to_set
      if action_set.size < possible_actions.size
        # TODO: Use own exception
        raise ArgumentError, "Duplicate, hidden bug?"
      end

      action_set
    end
  end
end
