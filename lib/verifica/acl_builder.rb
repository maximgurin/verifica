module Verifica
  class AclBuilder
    def initialize(initial_aces = EMPTY_ARRAY)
      @aces = initial_aces.dup
      freeze
    end

    def allow(sid, actions)
      @aces.concat(actions.map { |action| Ace.new(sid, action, true) })
      self
    end

    def deny(sid, actions)
      @aces.concat(actions.map { |action| Ace.new(sid, action, false) })
      self
    end

    def build
      Acl.new(@aces)
    end
  end
end
