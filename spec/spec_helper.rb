require 'simplecov'
SimpleCov.start

require 'omniauth-saml'
require 'rack/test'
require 'base64'
require 'nokogiri'
require File.expand_path('../shared/validating_method.rb', __FILE__)

RSpec.configure do |config|
  config.include Rack::Test::Methods
end

def load_xml(filename=:example_response)
  filename = File.expand_path(File.join('..', 'support', "#{filename.to_s}.xml"), __FILE__)
  Base64.encode64(IO.read(filename))
end

def load_xml_64(filename=:example_response)
  filename = File.expand_path(File.join('..', 'support', "#{filename.to_s}_64.txt"), __FILE__)
  IO.read(filename)
end
