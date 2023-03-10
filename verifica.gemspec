# frozen_string_literal: true

require_relative "lib/verifica/version"

Gem::Specification.new do |spec|
  spec.name          = "verifica"
  spec.authors       = ["Maxim Gurin"]
  spec.email         = ["mg@maximgurin.com"]
  spec.version       = Verifica::VERSION
  spec.license       = "MIT"

  spec.summary       = "The most scalable authorization solution for Ruby"
  spec.homepage      = "https://github.com/maximgurin/verifica"
  spec.files         = Dir["CHANGELOG.md", "LICENSE", "README.md", "verifica.gemspec", "lib/**/*"]
  spec.bindir        = "bin"
  spec.executables   = []
  spec.require_paths = ["lib"]
  spec.description   = <<~DESCRIPTION
    Verifica is Ruby's most scalable authorization solution, ready to handle sophisticated authorization rules.
    Verifica is framework and database agnostic and designed around Access Control Lists.
    ACL powers a straightforward and unified authorization flow for any user and resource,
    regardless of how tricky the authorization rules are.

    Verifica aims to solve the issue when authorization rules become too complex to be expressed in a single
    SQL query. And at the same time the database is too big to execute these rules in the application code.
  DESCRIPTION

  spec.metadata["allowed_push_host"]     = "https://rubygems.org"
  spec.metadata["homepage_uri"]          = spec.homepage
  spec.metadata["changelog_uri"]         = "https://github.com/maximgurin/verifica/blob/main/CHANGELOG.md"
  spec.metadata["source_code_uri"]       = "https://github.com/maximgurin/verifica"
  spec.metadata["bug_tracker_uri"]       = "https://github.com/maximgurin/verifica/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.required_ruby_version = ">= 3.0.0"

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "yard"
end
