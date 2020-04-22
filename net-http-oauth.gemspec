Gem::Specification.new do |s|
  s.name = 'net-http-oauth'
  s.version = '1.0.0'
  s.platform = Gem::Platform::RUBY
  s.authors = ['Tim Craft']
  s.email = ['mail@timcraft.com']
  s.homepage = 'http://github.com/timcraft/net-http-oauth'
  s.description = 'OAuth 1.0 signature algorithms for Net::HTTP requests'
  s.summary = 'See description'
  s.files = Dir.glob('{lib,spec}/**/*') + %w(README.md Rakefile net-http-oauth.gemspec)
  s.add_development_dependency('rake', '~> 10.0.3')
  s.require_path = 'lib'
end
