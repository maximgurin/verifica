module Verifica
  class Configuration
    attr_reader :resources

    def initialize
      @resources = []
    end

    def register_resource(type, possible_operations, acl_provider)
      resources << ResourceConfiguration.new(type, possible_operations, acl_provider)
      self
    end
  end
end
