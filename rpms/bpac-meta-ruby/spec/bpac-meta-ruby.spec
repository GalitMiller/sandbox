
Name:           bpac-meta-ruby
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Meta-package for Ruby 1.9.3 GEMs to run Bricata (snorby) application
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch


###
#   Ruby Execution Environment
###
Requires:       wkhtmltox
Requires:       passenger
Requires:       mod_passenger


###
#   Ruby 1.9.3 Components
###
Requires:       ruby193-ruby
Requires:       ruby193-ruby-devel
Requires:       ruby193-rubygem-actionmailer
Requires:       ruby193-rubygem-actionpack
Requires:       ruby193-rubygem-activemodel
Requires:       ruby193-rubygem-activerecord
Requires:       ruby193-rubygem-activeresource
Requires:       ruby193-rubygem-activesupport
Requires:       ruby193-rubygem-addressable
Requires:       ruby193-rubygem-ansi
Requires:       ruby193-rubygem-arel
Requires:       ruby193-rubygem-bcrypt-ruby
Requires:       ruby193-rubygem-bigdecimal
Requires:       ruby193-rubygem-builder
Requires:       ruby193-rubygem-bundler
Requires:       ruby193-rubygem-bundler-unload
Requires:       ruby193-rubygem-cancan
Requires:       ruby193-rubygem-capistrano
Requires:       ruby193-rubygem-capybara
Requires:       ruby193-rubygem-childprocess
Requires:       ruby193-rubygem-chronic
Requires:       ruby193-rubygem-closure-compiler
Requires:       ruby193-rubygem-daemons
Requires:       ruby193-rubygem-data_objects
Requires:       ruby193-rubygem-delayed_job
Requires:       ruby193-rubygem-devise
Requires:       ruby193-rubygem-devise_invitable
Requires:       ruby193-rubygem-diff-lcs
Requires:       ruby193-rubygem-dm-active_model
Requires:       ruby193-rubygem-dm-aggregates
Requires:       ruby193-rubygem-dm-ar-finders
Requires:       ruby193-rubygem-dm-chunked_query
Requires:       ruby193-rubygem-dm-constraints
Requires:       ruby193-rubygem-dm-core
Requires:       ruby193-rubygem-dm-devise
Requires:       ruby193-rubygem-dm-do-adapter
Requires:       ruby193-rubygem-dm-migrations
Requires:       ruby193-rubygem-dm-mysql-adapter
Requires:       ruby193-rubygem-dm-observer
Requires:       ruby193-rubygem-dm-pager
Requires:       ruby193-rubygem-dm-rails
Requires:       ruby193-rubygem-dm-serializer
Requires:       ruby193-rubygem-dm-timestamps
Requires:       ruby193-rubygem-dm-transactions
Requires:       ruby193-rubygem-dm-types
Requires:       ruby193-rubygem-dm-validations
Requires:       ruby193-rubygem-dm-visualizer
Requires:       ruby193-rubygem-dm-zone-types
Requires:       ruby193-rubygem-do_mysql
Requires:       ruby193-rubygem-env
Requires:       ruby193-rubygem-erubis
Requires:       ruby193-rubygem-eventmachine
Requires:       ruby193-rubygem-fastercsv
Requires:       ruby193-rubygem-ffi
Requires:       ruby193-rubygem-geoip
Requires:       ruby193-rubygem-highline
Requires:       ruby193-rubygem-hike
Requires:       ruby193-rubygem-home_run
Requires:       ruby193-rubygem-i18n
Requires:       ruby193-rubygem-io-console
Requires:       ruby193-rubygem-jammit
Requires:       ruby193-rubygem-jquery-rails
Requires:       ruby193-rubygem-json
Requires:       ruby193-rubygem-json_pure
Requires:       ruby193-rubygem-launchy
Requires:       ruby193-rubygem-letter_opener
Requires:       ruby193-rubygem-mail
Requires:       ruby193-rubygem-mime-types
Requires:       ruby193-rubygem-minitest
Requires:       ruby193-rubygem-multi_json
Requires:       ruby193-rubygem-netaddr
Requires:       ruby193-rubygem-net-dns
Requires:       ruby193-rubygem-net-scp
Requires:       ruby193-rubygem-net-sftp
Requires:       ruby193-rubygem-net-ssh
Requires:       ruby193-rubygem-net-ssh-gateway
Requires:       ruby193-rubygem-nokogiri
Requires:       ruby193-rubygem-open4
Requires:       ruby193-rubygem-orm_adapter
Requires:       ruby193-rubygem-pdfkit
Requires:       ruby193-rubygem-Platform
Requires:       ruby193-rubygem-polyglot
Requires:       ruby193-rubygem-POpen4
Requires:       ruby193-rubygem-rack
Requires:       ruby193-rubygem-rack-cache
Requires:       ruby193-rubygem-rack-mount
Requires:       ruby193-rubygem-rack-ssl
Requires:       ruby193-rubygem-rack-test
Requires:       ruby193-rubygem-rails
Requires:       ruby193-rubygem-rails_4_session_flash_backport
Requires:       ruby193-rubygem-railties
Requires:       ruby193-rubygem-rake
Requires:       ruby193-rubygem-rdoc
Requires:       ruby193-rubygem-RedCloth
Requires:       ruby193-rubygem-request_store
Requires:       ruby193-rubygem-rspec
Requires:       ruby193-rubygem-rspec-core
Requires:       ruby193-rubygem-rspec-expectations
Requires:       ruby193-rubygem-rspec-mocks
Requires:       ruby193-rubygem-rspec-rails
Requires:       ruby193-rubygem-rubycas-client
Requires:       ruby193-rubygem-rubygems-bundler
Requires:       ruby193-rubygem-ruby-graphviz
Requires:       ruby193-rubygem-rubyzip
Requires:       ruby193-rubygem-rvm
Requires:       ruby193-rubygems
Requires:       ruby193-rubygems-devel
Requires:       ruby193-rubygem-selenium-webdriver
Requires:       ruby193-rubygem-simple_form
Requires:       ruby193-rubygem-sprockets
Requires:       ruby193-rubygem-stringex
Requires:       ruby193-rubygem-thin
Requires:       ruby193-rubygem-thor
Requires:       ruby193-rubygem-tilt
Requires:       ruby193-rubygem-timezone_local
Requires:       ruby193-rubygem-treetop
Requires:       ruby193-rubygem-turn
Requires:       ruby193-rubygem-tzinfo
Requires:       ruby193-rubygem-uuidtools
Requires:       ruby193-rubygem-warden
Requires:       ruby193-rubygem-websocket
Requires:       ruby193-rubygem-whois
Requires:       ruby193-rubygem-xpath
Requires:       ruby193-rubygem-yui-compressor
Requires:       ruby193-ruby-irb
Requires:       ruby193-ruby-libs
Requires:       ruby193-ruby-tcltk
Requires:       ruby193-rubygem-delayed_job_data_mapper
Requires:       ruby193-rubygem-dm-is-read_only
Requires:       ruby193-rubygem-devise_cas_authenticatable
Requires:       ruby193-rubygem-ezprint-doc



%description
Installs as a dependency all Ruby 1.9.3 GEMs to run Bricata (snorby) application. The package itself contains no files.


%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

%clean
rm -rf "$RPM_BUILD_ROOT"

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

%changelog
* Mon Sep 14 2015 Roman Pavlyuk <rpavlyuk@softserveinc.com> - 1.5-4
- Initial version.
