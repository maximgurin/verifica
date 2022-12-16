module Verifica
  module Sid
    ANONYMOUS = "anonymous".freeze
    AUTHENTICATED = "authenticated".freeze
    ROOT = "root".freeze

    def anonymous
      ANONYMOUS
    end

    def authenticated
      AUTHENTICATED
    end

    def root
      ROOT
    end

    def user(user_id)
      "user:#{user_id}".freeze
    end

    def role(role_id)
      "role:#{role_id}".freeze
    end

    def organization(organization_id)
      "org:#{organization_id}".freeze
    end
  end
end
