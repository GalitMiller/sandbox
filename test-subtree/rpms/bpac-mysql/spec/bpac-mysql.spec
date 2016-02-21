
Name:           bpac-mysql
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Configuration file for MySQL and repairing of database
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

Requires:       mysql-server

%description

Configuration file for MySQL and service, which will repair MYSQL database at container start.


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

%attr(0755,root,root) /usr/bin/*.sh

/etc/my.cnf.d/bricata.cnf

/usr/lib/systemd/system/bpac-mysql-myisamcheck.service
/usr/lib/systemd/system/bpac-mysql-mysqlcheck.service

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
