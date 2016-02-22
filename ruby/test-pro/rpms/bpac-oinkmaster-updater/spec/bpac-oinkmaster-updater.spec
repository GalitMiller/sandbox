Name:           bpac-oinkmaster-updater
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        ET Rules nightly update job using OINKMASTER tool
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

Requires:	oinkmaster
Requires:	cronie

%description

ET Rules nightly update job using OINKMASTER tool


%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

cp -a src/* "$RPM_BUILD_ROOT/"

%clean
rm -rf "$RPM_BUILD_ROOT"

%check

test/test_all.sh

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

%attr(0755,root,root) /usr/bin/*.sh

%attr(0644,root,root) /var/spool/cron/*

%attr(0644,root,root) /etc/logrotate.d/oinkmaster-updater

%changelog
* Wed Jul 03 2015 Roman Pavlyuk <rpavlyuk@softserveinc.com> - 1.0-1
- Initial version.
