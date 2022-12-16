# frozen_string_literal: true

require "pathname"
SPEC_ROOT = Pathname(__dir__).realpath.freeze

require_relative "support/coverage"
require_relative "support/warnings"
require_relative "support/rspec_options"

require "verifica"
