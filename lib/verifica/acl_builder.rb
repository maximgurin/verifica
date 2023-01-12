# frozen_string_literal: true

module Verifica
  # Builder that holds mutable list of Access Control Entries and methods to add new entries
  #
  # @see Acl.build Usage examples
  #
  # @api public
  class AclBuilder
    # @note Use {Acl.build} or {Acl#build} instead of this constructor directly
    #
    # @api public
    def initialize(initial_aces = EMPTY_ARRAY)
      @aces = initial_aces.dup
      freeze
    end

    # Add Access Control Entries that allow particular actions for the given Security Identifier
    #
    # @example
    #   builder = AclBuilder.new
    #     .allow("anonymous", [:read])
    #     .allow("root", [:read, :write, :delete])
    #   acl = builder.build
    #
    # @param sid [String] Security Identifier
    # @param actions [Enumerable<Symbol>, Enumerable<String>] list of actions allowed for the given SID
    #
    # @return [self]
    #
    # @api public
    def allow(sid, actions)
      @aces.concat(actions.map { |action| Ace.new(sid, action, true) })
      self
    end

    # Add Access Control Entries that deny particular actions for the given Security Identifier
    #
    # @example
    #   builder = Verifica::AclBuilder.new
    #     .deny("country:US", [:read, :comment])
    #     .deny("country:CA", [:read, :comment])
    #   acl = builder.build
    #
    # @param sid [String] Security Identifier
    # @param actions [Enumerable<Symbol>, Enumerable<String>] list of actions denied for the given SID
    #
    # @return [self]
    #
    # @api public
    def deny(sid, actions)
      @aces.concat(actions.map { |action| Ace.new(sid, action, false) })
      self
    end

    # @return [Acl] a new, immutable Access Control List
    #
    # @api public
    def build
      Acl.new(@aces)
    end
  end
end
