# frozen_string_literal: true

module Verifica
  module Sid
    ANONYMOUS_SID = "anonymous"
    AUTHENTICATED_SID = "authenticated"
    ROOT_SID = "root"

    def anonymous_sid
      ANONYMOUS_SID
    end

    def authenticated_sid
      AUTHENTICATED_SID
    end

    def root_sid
      ROOT_SID
    end

    def user_sid(user_id)
      "user:#{user_id}".freeze
    end

    def role_sid(role_id)
      "role:#{role_id}".freeze
    end

    def organization_sid(organization_id)
      "org:#{organization_id}".freeze
    end
  end
end
