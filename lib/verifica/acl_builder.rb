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

    def allow_anonymous(actions)
      allow(Sid.anonymous, actions)
      self
    end

    def allow_authenticated(actions)
      allow(Sid.authenticated, actions)
      self
    end

    def allow_user(user_id, actions)
      allow(Sid.user(user_id), actions)
      self
    end

    def allow_organization(organization_id, actions)
      allow(Sid.organization(organization_id), actions)
      self
    end

    def allow_root(actions)
      allow(Sid.root, actions)
      self
    end

    def build
      Acl.new(@aces)
    end
  end
end
