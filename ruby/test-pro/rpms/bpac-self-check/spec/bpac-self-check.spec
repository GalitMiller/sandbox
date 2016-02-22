
Name:           bpac-self-check
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Execute some basic tests, e.g. are services running?
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

Requires:       cronie
Requires:       nagios-plugins-http

%description

Package contains script to check status of services and report status via /static/SELFCHECK.txt page.


%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

cp -a src/* "$RPM_BUILD_ROOT/"

%clean
rm -rf "$RPM_BUILD_ROOT"

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

/etc/cron.d/self-check

%attr(0755,root,root) /usr/bin/*.sh
%attr(0755,root,root) /usr/lib/bpac-self-check

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
