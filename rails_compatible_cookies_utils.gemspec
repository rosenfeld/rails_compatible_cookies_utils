# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rails_compatible_cookies_utils/version'

Gem::Specification.new do |spec|
  spec.name          = 'rails_compatible_cookies_utils'
  spec.version       = RailsCompatibleCookiesUtils::VERSION
  spec.authors       = ['Rodrigo Rosenfeld Rosas']
  spec.email         = ['rr.rosas@gmail.com']

  spec.summary       = %q{Provides utility methods to read and write cookies shared with a Rails app}
  spec.homepage      = 'https://github.com/rosenfeld/rails_compatible_cookies_utils'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^spec/}) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.11'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
end
