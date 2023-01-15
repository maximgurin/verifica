# frozen_string_literal: true

require "set"
require_relative "ace"
require_relative "acl_builder"

module Verifica
  # Access Control List (ACL)
  #
  # Access Control List consists of Access Control Entities (ACEs) and defines which
  # actions are allowed or denied for particular Security Identifiers (SIDs).
  #
  # ACL is typically associated with a resource (e.g. Post, Comment, Order) and specifies
  # which users (or external services, or API clients) are allowed to do what actions on the given resource.
  #
  # @see Ace
  # @see Sid
  #
  # @api public
  class Acl
    # Creates a new {AclBuilder} and yields it to the given block.
    #
    # @example
    #   acl = Verifica::Acl.build do |acl|
    #     acl.allow "anonymous", [:read]
    #     acl.allow "authenticated", [:read, :comment]
    #     acl.deny "country:US", [:read, :comment]
    #   end
    #
    # @return [Acl] Access Control List created by builder
    #
    # @api public
    def self.build
      builder = AclBuilder.new
      yield builder
      builder.build
    end

    attr_reader :aces
    protected :aces

    # Creates a new Access Control List with immutable state.
    # @note Use {.build} instead of this constructor directly.
    #
    # @param aces [Array<Ace>] list of Access Control Entries
    #
    # @api public
    def initialize(aces)
      @aces = Set.new(aces).freeze
      @allow_deny_by_action = prepare_index.freeze
      @allowed_actions = Set.new
      @allow_deny_by_action.each do |action, allow_deny|
        @allowed_actions.add(action) unless allow_deny[:allowed_sids].empty?

        allow_deny[:allowed_sids].freeze
        allow_deny[:denied_sids].freeze
        allow_deny.freeze
      end

      @allowed_actions.freeze
      freeze
    end

    # Checks whether the action is allowed for given Security Identifiers.
    # For action to be allowed all 3 conditions should be met:
    #
    # * ACL and SIDs are not empty
    # * ACL contains at least one entry that allow given action for any of the SIDs
    # * ACL contains no entries that deny given action for any of the SIDs
    #
    # @param action [Symbol, String] action to check
    # @param sids [Array<String>, Set<String>] list of Security Identifiers to match for
    #
    # @return [Boolean] true if action is allowed
    #
    # @api public
    def action_allowed?(action, sids)
      return false if empty? || sids.empty?

      action = action.to_sym
      allow_deny = @allow_deny_by_action[action]

      return false if allow_deny.nil? || !@allowed_actions.include?(action)

      sids = sids.to_set
      allow_deny[:allowed_sids].intersect?(sids) && !allow_deny[:denied_sids].intersect?(sids)
    end

    # The opposite of {#action_allowed?}
    #
    # @api public
    def action_denied?(action, sids)
      !action_allowed?(action, sids)
    end

    # @note Checking allowed SIDs isn't enough to determine whether the action is allowed.
    #   You need to always check {#denied_sids} as well.
    #
    # @param action (see #action_allowed?)
    #
    # @return [Array<String>] array of Security Identifiers allowed for a given action or empty array if none
    #
    # @api public
    def allowed_sids(action)
      sids = @allow_deny_by_action.dig(action.to_sym, :allowed_sids)
      sids.nil? ? EMPTY_ARRAY : sids.to_a
    end

    # @note Checking denied SIDs isn't enough to determine whether the action is allowed.
    #   You need to always check {#allowed_sids} as well.
    #
    # @param action (see #action_allowed?)
    #
    # @return [Array<String>] array of Security Identifiers denied for a given action or empty array if none
    #
    # @api public
    def denied_sids(action)
      sids = @allow_deny_by_action.dig(action.to_sym, :denied_sids)
      sids.nil? ? EMPTY_ARRAY : sids.to_a
    end

    # @param sids (see #action_allowed?)
    #
    # @return [Array<Symbol>] array of actions allowed for given Security Identifiers or empty array if none
    #
    # @api public
    def allowed_actions(sids)
      return EMPTY_ARRAY if sids.empty?

      @allowed_actions.select { |action| action_allowed?(action, sids) }
    end

    # Creates a new {AclBuilder}, adds existing entries to it and yields it to the given block.
    # Use this method to extend an existing ACL with additional entries
    #
    # @example
    #   base_acl = Verifica::Acl.build do |acl|
    #     acl.allow "superuser", [:read, :write, :delete]
    #   end
    #
    #   extended_acl = base_acl.build do |acl|
    #     acl.allow "anonymous", [:read]
    #     acl.allow "authenticated", [:read, :comment]
    #   end
    #
    # @return [Acl] new Access Control List created by builder
    #
    # @api public
    def build
      builder = AclBuilder.new(to_a)
      yield builder
      builder.build
    end

    # @example
    #   acl = Verifica::Acl.build { |acl| acl.allow "root", [:read, :write] }
    #   acl.to_a.map(:to_h)
    #   # => [{:sid=>"root", :action=>:read, :allow=>true}, {:sid=>"root", :action=>:write, :allow=>true}]
    #
    # @return [Array<Ace>] a new array representing +self+
    #
    # @api public
    def to_a
      @aces.to_a
    end

    # @return [Boolean] true if there are no entries in +self+
    #
    # @api public
    def empty?
      @aces.empty?
    end

    # @return [Integer] the count of entries in +self+
    #
    # @api public
    def length
      @aces.length
    end
    alias_method :size, :length

    def to_s
      @aces.map(&:to_h).to_s
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      self.class == other.class &&
        @aces == other.aces
    end

    def hash
      [self.class, @aces].hash
    end

    private def prepare_index
      @aces.each_with_object({}) do |ace, index|
        action = ace.action
        allow_deny = index.fetch(action) { {allowed_sids: Set.new, denied_sids: Set.new}.freeze }
        allow_deny[ace.allow? ? :allowed_sids : :denied_sids].add(ace.sid)
        index[action] = allow_deny
      end
    end
  end
end
