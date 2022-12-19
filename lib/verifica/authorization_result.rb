# frozen_string_literal: true

module Verifica
  class AuthorizationResult
    attr_reader :subject, :subject_sids, :resource, :action, :acl, :context

    def initialize(subject, resource, action, acl, **context)
      @subject = subject
      sids = Verifica.subject_sids(subject)
      @subject_sids = sids.map{ _1.dup.freeze }.freeze
      @resource = resource
      @action = action
      @acl = acl
      @context = context
      @success = acl.action_allowed?(action, @subject_sids)
      freeze
    end

    def success?
      @success
    end

    def failure?
      !success?
    end

    def subject_type
      subject.subject_type.to_sym
    end

    def subject_id
      subject.subject_id
    end

    def resource_type
      resource.resource_type.to_sym
    end

    def resource_id
      resource.resource_id
    end

    def allowed_actions
      acl.allowed_actions(subject_sids)
    end
  end
end
