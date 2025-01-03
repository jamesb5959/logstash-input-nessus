Gem::Specification.new do |s|
  s.name          = 'logstash-input-nessus'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Logstash Input Plugin for Nessus'
  s.description   = 'A custom plugin for Nessus'
  s.homepage      = 'https://github.com/jamesb5959/logstash-input-nessus'
  s.authors       = ['Bradley Beltran']
  s.email         = 'jamesb5959@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'stud', '>= 0.0.22'

  # development dependency for the JRuby platform
  if RUBY_PLATFORM == 'java'
    s.add_development_dependency 'logstash-devutils', '>= 0.0.16'
  end

end
