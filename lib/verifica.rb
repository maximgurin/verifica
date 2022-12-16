# frozen_string_literal: true

require_relative "verifica/ace"
require_relative "verifica/acl"
require_relative "verifica/acl_builder"
require_relative "verifica/authorization_result"
require_relative "verifica/configuration"
require_relative "verifica/engine"
require_relative "verifica/errors"
require_relative "verifica/resource_configuration"
require_relative "verifica/sid"
require_relative "verifica/version"

module Verifica
  EMPTY_ARRAY = [].freeze
  EMPTY_SET = Set.new.freeze
  private_constant :EMPTY_ARRAY, :EMPTY_SET

  EMPTY_ACL = Verifica::Acl.new(EMPTY_ARRAY).freeze

  def self.engine
    config = Configuration.new
    yield config
    Engine.new(config.resources)
  end
end
