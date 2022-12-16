module Verifica
  class AclBuilder
    def initialize
      @aces = []
      freeze
    end

    def allow(sid, operations)
      @aces.concat(operations.map { |op| Ace.new(sid, op, true) })
      self
    end

    def deny(sid, operations)
      @aces.concat(operations.map { |op| Ace.new(sid, op, false) })
      self
    end

    def allow_anonymous(operations)
      allow(Sid.anonymous, operations)
      self
    end

    def allow_authenticated(operations)
      allow(Sid.authenticated, operations)
      self
    end

    def allow_user(user_id, operations)
      allow(Sid.user(user_id), operations)
      self
    end

    def allow_organization(organization_id, operations)
      allow(Sid.organization(organization_id), operations)
      self
    end

    def allow_root(operations)
      allow(Sid.root, operations)
      self
    end

    def build
      Acl.new(@aces)
    end
  end
end
