require "set"

module Verifica
  class ResourceConfiguration
    attr_reader :resource_type, :possible_actions, :acl_provider

    def initialize(resource_type, possible_actions, acl_provider)
      @resource_type = resource_type.to_sym
      @possible_actions = action_set(possible_actions).freeze
      if acl_provider.nil?
        raise Error, "'#{@resource_type}' resource acl_provider should not be nil"
      end
      @acl_provider = acl_provider
      freeze
    end

    private def action_set(possible_actions)
      if possible_actions.empty?
        raise Error, "Empty possible actions for '#{@resource_type}' resource. Probably a bug?"
      end

      action_set = possible_actions.map(&:to_sym).to_set
      if action_set.size < possible_actions.size
        duplicates = possible_actions.tally.select { |_, count| count > 1 }.keys
        raise Error, "'#{duplicates}' possible actions for '#{@resource_type}' resource are specified several times. " \
          "Probably code copy-paste and a bug?"
      end

      action_set
    end
  end
end
