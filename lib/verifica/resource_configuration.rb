# frozen_string_literal: true

require "set"

module Verifica
  # Configuration object for resources registered in {Authorizer}
  #
  # @see Verifica.authorizer Usage examples
  # @note Use {Configuration#register_resource} instead of this class directly
  #
  # @api public
  class ResourceConfiguration
    # @return [Symbol] type of the resource
    #
    # @api public
    attr_reader :resource_type

    # @return [Set<Symbol>] set of actions possible for this resource type
    #
    # @api public
    attr_reader :possible_actions

    # @return [#call] Access Control List provider for this resource type
    #
    # @api public
    attr_reader :acl_provider

    # @see Verifica.authorizer Usage examples
    # @note Use {Configuration#register_resource} instead of this constructor directly
    #
    # @api public
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
