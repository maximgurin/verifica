# frozen_string_literal: true

module Verifica
  class AuthorizationResult
    attr_reader :subject, :subject_sids, :resource, :action, :acl, :context

    def initialize(subject, resource, action, acl, **context)
      @subject = subject
      if subject.nil?
        # TODO: Use own exception
        raise ArgumentError, "Subject should not be nil"
      end
      @subject_sids = subject.subject_sids
      unless @subject_sids.is_a?(Array) || @subject_sids.is_a?(Set)
        # TODO: Use own exception
        raise ArgumentError, "Subject should respond to subject_sids call and return Array or Set of SIDs"
      end
      @resource = resource
      @action = action
      @acl = acl
      @context = context
      freeze
    end

    def success?
      acl.action_allowed?(action, @subject_sids)
    end

    def failure?
      !success?
    end

    def subject_type
      subject.subject_type
    end

    def subject_id
      subject.subject_id
    end

    def resource_type
      resource.resource_type
    end

    def resource_id
      resource.resource_id
    end
  end
end
