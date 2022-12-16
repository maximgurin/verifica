require "set"

module Verifica
  class Acl
    def self.build
      builder = AclBuilder.new
      yield builder
      builder.build
    end

    def initialize(aces)
      @aces = aces.uniq.freeze
      @index_by_ops = prepare_index.freeze
      @allowed_operations = Set.new
      @index_by_ops.each do |op, allow_deny|
        @allowed_operations.add(op) unless allow_deny[:allowed_sids].empty?

        allow_deny[:allowed_sids].freeze
        allow_deny[:denied_sids].freeze
        allow_deny.freeze
      end

      @allowed_operations.freeze
      freeze
    end

    def operation_allowed?(operation, sids)
      return false if empty? || sids.empty?

      operation = operation.to_sym
      allow_deny = @index_by_ops[operation]

      return false if allow_deny.nil? || !@allowed_operations.include?(operation)

      allow_deny[:allowed_sids].intersect?(sids) && !allow_deny[:denied_sids].intersect?(sids)
    end

    def operation_denied?(operation, sids)
      !operation_allowed?(operation, sids)
    end

    def allowed_sids(operation)
      sids = @index_by_ops.dig(operation.to_sym, :allowed_sids)
      sids.nil? ? EMPTY_SET : sids
    end

    def denied_sids(operation)
      sids = @index_by_ops.dig(operation.to_sym, :denied_sids)
      sids.nil? ? EMPTY_SET : sids
    end

    def allowed_operations(sids)
      return EMPTY_SET if sids.empty?

      @allowed_operations.select { |op| operation_allowed?(op, sids) }
    end

    def to_a
      @aces
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
        @aces == other.to_a
    end

    def hash
      [self.class, @aces].hash
    end

    private

    def prepare_index
      @aces.each_with_object({}) do |ace, index|
        operation = ace.operation
        allow_deny = index.fetch(operation) { {allowed_sids: Set.new, denied_sids: Set.new}.freeze }
        allow_deny[ace.allow? ? :allowed_sids : :denied_sids].add(ace.sid)
        index[operation] = allow_deny
      end
    end
  end
end
