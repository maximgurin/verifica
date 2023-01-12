# frozen_string_literal: true

module Verifica
  # Outcome of the authorization, either successful or failed.
  # Memoizes the state of variables that affected the decision. Could show why the authorization
  # was successful or failed even if the concerned objects have changed.
  #
  # @see Authorizer#authorize
  #
  # @api public
  class AuthorizationResult
    # @return [Object] subject of the authorization (e.g. current user, external service)
    #
    # @api public
    attr_reader :subject

    # @return [Object] subject ID returned by +subject.subject_id+
    #
    # @api public
    attr_reader :subject_id

    # @return [Symbol, nil] subject type returned by +subject.subject_type+
    #
    # @api public
    attr_reader :subject_type

    # @return [Array<String>] array of subject Security Identifiers returned by +subject.subject_sids+
    #
    # @api public
    attr_reader :subject_sids

    # @return [Object] resource on which {#subject} attempted to perform {#action}
    #
    # @api public
    attr_reader :resource

    # @return [Object] resource ID returned by +resource.resource_id+
    #
    # @api public
    attr_reader :resource_id

    # @return [Symbol] resource type returned by resource#resource_type
    #
    # @api public
    attr_reader :resource_type

    # @return [Symbol] action that {#subject} attempted to perform on the {#resource}
    #
    # @api public
    attr_reader :action

    # @return [Acl] Access Control List returned by ACL provider registered for this {#resource_type} in {Authorizer}
    #
    # @api public
    attr_reader :acl

    # @return [Hash] any additional keyword arguments that have been passed to the authorization call
    #
    # @see Authorizer#authorize
    #
    # @api public
    attr_reader :context

    # @api private
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

    # @return [Boolean] true if given {#action} is allowed for given {#subject}
    #
    # @api public
    def success?
      @success
    end

    # @return [Boolean] true if given {#action} is denied for given {#subject}
    #
    # @api public
    def failure?
      !success?
    end

    # @see Acl#allowed_actions
    #
    # @return [Array<Symbol>] array of actions allowed for given {#subject} or empty array if none
    #
    # @api public
    def allowed_actions
      acl.allowed_actions(subject_sids)
    end

    # @return [String] human-readable description of authorization result. Includes subject, resource, and outcome
    #
    # @api public
    def message
      status = success? ? "SUCCESS" : "FAILURE"
      "Authorization #{status}. Subject '#{subject_type}' id='#{subject_id}'. Resource '#{resource_type}' " \
        "id='#{resource_id}'. Action '#{action}'"
    end

    # @return [String] detailed, human-readable description of authorization result.
    #   Includes subject, resource, resource ACL, and explains the reason why authorization was successful or failed.
    #   Extremely useful for debugging.
    #
    # @api public
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
