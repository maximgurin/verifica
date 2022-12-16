module Verifica
  class Ace
    attr_reader :sid, :action

    def initialize(sid, action, allow)
      @sid = sid.dup.freeze
      @action = action.to_sym
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
      { sid: @sid, action: @action, allow: @allow }
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      self.class == other.class &&
        @sid == other.sid &&
        @action == other.action &&
        @allow == other.allow?
    end

    def hash
      [self.class, @sid, @action, @allow].hash
    end
  end
end
