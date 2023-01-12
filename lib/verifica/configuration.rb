# frozen_string_literal: true

require_relative "resource_configuration"

module Verifica
  # Configuration object for {Authorizer}, holds list of registered resources and other params
  #
  # @see Verifica.authorizer Usage examples
  #
  # @api public
  class Configuration
    # @return [Array<ResourceConfiguration>] array of registered resources
    #
    # @api public
    attr_reader :resources

    # @note Use {Verifica.authorizer} instead of this constructor directly
    #
    # @api public
    def initialize
      @resources = []
    end

    # Register a new resource supported by {Authorizer}
    #
    # @see Verifica.authorizer Usage examples
    #
    # @param type [Symbol, String] type of the resource
    # @param possible_actions [Enumerable<Symbol>, Enumerable<String>] list of actions possible for this resource type
    # @param acl_provider [#call] Access Control List provider for this resource type.
    #   Could be any object that responds to +#call(resource, **)+ and returns {Acl}
    #
    # @return [self]
    #
    # @api public
    def register_resource(type, possible_actions, acl_provider)
      resources << ResourceConfiguration.new(type, possible_actions, acl_provider)
      self
    end
  end
end
