# frozen_string_literal: true

RSpec.describe Verifica::Sid do
  subject(:sid) { Class.new { extend Verifica::Sid } }

  %i[user_sid role_sid organization_sid].each do |method|
    it "nil argument is rejected by ##{method}" do
      expect { sid.send(method, nil) }.to raise_error(ArgumentError)
    end
  end
end
