# frozen_string_literal: true

module Verifica
  # Base class for all Verifica exceptions
  #
  # @api public
  class Error < StandardError
    # @return [String] detailed description of the error if it's available or +message+ if not
    #
    # @api public
    def explain
      message
    end
  end

  # Raised when {#action} on the given {#resource} isn't allowed for authorization {#subject} (e.g. current user)
  #
  # @api public
  class AuthorizationError < Error
    # @api private
    attr_reader :result

    # @api private
    def initialize(result)
      @result = result
      super(result.message)
    end

    # (see AuthorizationResult#subject)
    def subject
      result.subject
    end

    # (see AuthorizationResult#subject_type)
    def subject_type
      result.subject_type
    end

    # (see AuthorizationResult#subject_id)
    def subject_id
      result.subject_id
    end

    # (see AuthorizationResult#subject_sids)
    def subject_sids
      result.subject_sids
    end

    # (see AuthorizationResult#resource)
    def resource
      result.resource
    end

    # (see AuthorizationResult#resource_type)
    def resource_type
      result.resource_type
    end

    # (see AuthorizationResult#resource_id)
    def resource_id
      result.resource_id
    end

    # (see AuthorizationResult#action)
    def action
      result.action
    end

    # (see AuthorizationResult#acl)
    def acl
      result.acl
    end

    # (see AuthorizationResult#context)
    def context
      result.context
    end

    # (see AuthorizationResult#explain)
    def explain
      result.explain
    end
  end
end
