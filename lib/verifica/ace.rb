# frozen_string_literal: true

module Verifica
  # Access Control Entry (ACE)
  #
  # ACE is a minimal unit of the Access Control List (ACL) that defines whether or not a specific action
  # is allowed for a particular Security Identifier (SID).
  #
  # @see Acl
  # @see Sid
  #
  # @api public
  class Ace
    # @return [String] Security Identifier (SID)
    #
    # @api public
    attr_reader :sid

    # @return [Symbol] Action which is allowed or denied
    #
    # @api public
    attr_reader :action

    # Creates a new Access Control Entry with immutable state
    #
    # @param sid [String] Security Identifier (SID), typically String,
    #   but could be any object with implemented equality methods and #hash
    # @param action [Symbol, String] action which is allowed or denied for given SID
    # @param allow [Boolean] allow or deny given action for given SID
    #
    # @api public
    def initialize(sid, action, allow)
      @sid = sid.dup.freeze
      @action = action.to_sym
      @allow = allow
      freeze
    end

    # @return [Boolean] true if the action is allowed
    #
    # @api public
    def allow?
      @allow
    end

    # @return [Boolean] true if the action is denied
    #
    # @api public
    def deny?
      !allow?
    end

    # @return [Hash] a new hash representing +self+
    #
    # @api public
    def to_h
      {sid: @sid, action: @action, allow: @allow}
    end

    def to_s
      to_h.to_s
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      self.class == other.class &&
        @sid == other.sid &&
        @action == other.action &&
        @allow == other.allow?
    end

    def hash
      [self.class, @sid, @action, @allow].hash
    end
  end
end
