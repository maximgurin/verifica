# frozen_string_literal: true

module Verifica
  class AuthorizationResult
    attr_reader :subject, :subject_id, :subject_type, :subject_sids,
      :resource, :resource_id, :resource_type, :action, :acl, :context

    def initialize(subject, resource, action, acl, **context)
      @subject = subject
      sids = Verifica.subject_sids(subject, **context)
      @subject_sids = sids.map { _1.dup.freeze }.freeze
      @subject_id = subject.subject_id.dup.freeze
      @subject_type = subject.subject_type&.to_sym
      @resource = resource
      @resource_id = resource.resource_id.dup.freeze
      @resource_type = resource.resource_type.to_sym
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

    def allowed_actions
      acl.allowed_actions(subject_sids)
    end

    def message
      status = success? ? "SUCCESS" : "FAILURE"
      "Authorization #{status}. Subject '#{subject_type}' id='#{subject_id}'. Resource '#{resource_type}' " \
        "id='#{resource_id}'. Action '#{action}'"
    end

    def explain
      <<~MESSAGE
        #{message}

        \s\sSubject SIDs (#{subject_sids.empty? ? "empty" : subject_sids.size}):
        \s\s\s\s#{subject_sids}

        \s\sContext:
        \s\s\s\s#{context}

        \s\sResource ACL (#{acl.empty? ? "empty" : acl.size}):
        #{acl.to_a.map { "\s\s\s\s#{_1}" }.join("\n")}

        Reason: #{reason_message}
      MESSAGE
    end

    private def reason_message
      if success?
        sids = acl.allowed_sids(action).intersection(subject_sids).to_a
        return "subject SID(s) #{sids} allowed for '#{action}' action. No SIDs denied among subject SIDs"
      end

      return "resource ACL is empty, no actions allowed for any subject" if acl.empty?
      return "subject SIDs are empty, no actions allowed for any resource" if subject_sids.empty?

      denied = acl.denied_sids(action).intersection(subject_sids).to_a
      if denied.empty?
        "among #{subject_sids.size} subject SID(s), none is listed as allowed for '#{action}' action"
      else
        "subject SID(s) #{denied} denied for '#{action}' action. Denied SIDs always win regardless of allowed SIDs"
      end
    end
  end
end
