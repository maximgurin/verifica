module Verifica
  # base class for all Verifica exceptions
  class Error < StandardError; end

  class UnauthorizedError < Error; end
end