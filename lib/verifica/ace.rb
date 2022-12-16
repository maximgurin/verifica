module Verifica
  class Ace
    attr_reader :sid, :operation

    def initialize(sid, operation, allow)
      @sid = sid.dup.freeze
      @operation = operation.to_sym
      @allow = allow
      freeze
    end

    def allow?
      @allow
    end

    def deny?
      !allow?
    end

    def to_h
      { sid: @sid, operation: @operation, allow: @allow }
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      self.class == other.class &&
        @sid == other.sid &&
        @operation == other.operation &&
        @allow == other.allow?
    end

    def hash
      [self.class, @sid, @operation, @allow].hash
    end
  end
end
