module Verifica
  # base class for all Verifica exceptions
  class Error < StandardError; end

  class AuthorizationError < Error; end
end
