
Name:           bpac-webapp
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Frontend for BPAC application.
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

BuildRequires:  npm
BuildRequires:  git

BuildRequires:  node-gulp
BuildRequires:	node-gulp-rename
BuildRequires:  node-gulp-sass
BuildRequires:  node-gulp-clean
BuildRequires:  node-gulp-uglify
BuildRequires:  node-gulp-concat
BuildRequires:  node-gulp-jshint
BuildRequires:  node-gulp-minify-css
BuildRequires:  node-gulp-minify-html
BuildRequires:  node-jshint-stylish
BuildRequires:  node-run-sequence
BuildRequires:  node-gulp-csslint
BuildRequires:  node-event-stream
BuildRequires:  node-gulp-if
BuildRequires:  node-gulp-newer
BuildRequires:  node-gulp-connect
BuildRequires:  node-gulp-flatten
BuildRequires:  node-gulp-jsonminify
BuildRequires:  node-gulp-ng-html2js
BuildRequires:  node-gulp-jasmine
BuildRequires:  node-gulp-karma
BuildRequires:  node-gulp-expect-file
BuildRequires:  node-karma
BuildRequires:  node-karma-jasmine
BuildRequires:  node-karma-phantomjs-launcher
BuildRequires:  node-karma-chrome-launcher
BuildRequires:  node-karma-firefox-launcher
BuildRequires:  node-karma-junit-reporter
BuildRequires:  node-karma-coverage
BuildRequires:  node-karma-ng-html2js-preprocessor
BuildRequires:  node-gulp-protractor
BuildRequires:  node-protractor
BuildRequires:  node-karma-phantomjs-shim

BuildRequires:  bower-angular
BuildRequires:  bower-angular-resource
BuildRequires:  bower-angular-route
BuildRequires:  bower-bootstrap-sass
BuildRequires:  bower-angular-ui-bootstrap-bower
BuildRequires:  bower-ng-table
BuildRequires:  bower-i18next
BuildRequires:  bower-ng-i18next
BuildRequires:  bower-angular-moment
BuildRequires:  bower-ng-scrollable
BuildRequires:  bower-angular-bootstrap-colorpicker
BuildRequires:  bower-angular-mocks
BuildRequires:  bower-jasmine-jquery
BuildRequires:  bower-jquery
BuildRequires:  bower-moment
BuildRequires:  bower-angular-cookies


%description

Frontend for BPAC application written in javascript.


%prep
%setup -qn webapp

%build

# Use packaged node modules
rm -rf node_modules
mkdir -p node_modules
for I in \
  event-stream  gulp-csslint  gulp-jsonminify   gulp-ng-html2js  karma                   karma-junit-reporter           \
  gulp          gulp-flatten  gulp-karma        gulp-protractor  karma-chrome-launcher   karma-ng-html2js-preprocessor  \
  gulp-clean    gulp-if       gulp-minify-css   gulp-sass        karma-coverage          karma-phantomjs-launcher       \
  gulp-concat   gulp-jasmine  gulp-minify-html  gulp-uglify      karma-firefox-launcher  protractor                     \
  gulp-connect  gulp-jshint   gulp-newer        jshint-stylish   karma-jasmine           run-sequence                   \
  gulp-expect-file karma-phantomjs-shim		gulp-rename
do
  ln -sf "/usr/lib/node_modules/$I" "node_modules/$I"
done

# Use packaged bower components
rm -rf bower_components
mkdir -p bower_components
for I in \
  angular \
  angular-resource \
  angular-route \
  bootstrap-sass \
  angular-ui-bootstrap-bower \
  ng-table \
  i18next \
  ng-i18next \
  angular-moment \
  ng-scrollable \
  angular-bootstrap-colorpicker \
  angular-mocks \
  jasmine-jquery \
  jquery \
  moment \
  angular-cookies
do
  ln -sf "/usr/lib/bower_components/$I" "bower_components/$I"
done

# Compile application
make gulp_build_prod

sed -i "s/@VERSION@/%{?bpacver}%{!?bpacver:1.0}/g" target/index.html

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT/var/www/webapp/"

cp -a target "$RPM_BUILD_ROOT/var/www/webapp/"

%clean
rm -rf "$RPM_BUILD_ROOT"

%check
# Run unit tests using Karma and PhantomJS
make test

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

/var/www/webapp/target

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
