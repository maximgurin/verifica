require "set"

module Verifica
  class Acl
    def self.build
      builder = AclBuilder.new
      yield builder
      builder.build
    end

    protected attr_reader :aces

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

    def action_allowed?(action, sids)
      return false if empty? || sids.empty?

      action = action.to_sym
      allow_deny = @allow_deny_by_action[action]

      return false if allow_deny.nil? || !@allowed_actions.include?(action)

      allow_deny[:allowed_sids].intersect?(sids) && !allow_deny[:denied_sids].intersect?(sids)
    end

    def action_denied?(action, sids)
      !action_allowed?(action, sids)
    end

    def allowed_sids(action)
      sids = @allow_deny_by_action.dig(action.to_sym, :allowed_sids)
      sids.nil? ? EMPTY_SET : sids
    end

    def denied_sids(action)
      sids = @allow_deny_by_action.dig(action.to_sym, :denied_sids)
      sids.nil? ? EMPTY_SET : sids
    end

    def allowed_actions(sids)
      return EMPTY_SET if sids.empty?

      @allowed_actions.select { |action| action_allowed?(action, sids) }
    end

    def build
      builder = AclBuilder.new(to_a)
      yield builder
      builder.build
    end

    def to_a
      @aces.to_a
    end

    def to_s
      @aces.map(&:to_h).to_s
    end

    def empty?
      @aces.empty?
    end

    def length
      @aces.length
    end
    alias size length

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
