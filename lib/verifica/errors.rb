module Verifica
  # base class for all Verifica exceptions
  class Error < StandardError
    def explain
      message
    end
  end

  class AuthorizationError < Error
    attr_reader :result

    def initialize(result)
      @result = result
      super(result.message)
    end

    def subject
      result.subject
    end

    def subject_type
      result.subject_type
    end

    def subject_id
      result.subject_id
    end

    def subject_sids
      result.subject_sids
    end

    def resource
      result.resource
    end

    def resource_type
      result.resource_type
    end

    def resource_id
      result.resource_id
    end

    def action
      result.action
    end

    def acl
      result.acl
    end

    def context
      result.context
    end

    def explain
      result.explain
    end
  end
end
