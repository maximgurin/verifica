module Verifica
  class AclBuilder
    def initialize
      @aces = []
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
