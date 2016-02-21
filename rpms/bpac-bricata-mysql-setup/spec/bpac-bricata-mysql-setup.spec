
Name:           bpac-bricata-mysql-setup
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Restore MySQL database from dump.
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

# Post script requires mysql server and client to restore database at installation time
PreReq:         mysql-server


%description

Restore MySQL database from dump. After first installation, this package can be deleted.


%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

cp -a src/* "$RPM_BUILD_ROOT/"

%clean
rm -rf "$RPM_BUILD_ROOT"

%post
if [ "$1" -eq 1 ]
then # Installation
  bricata-mysql-setup.sh /var/lib/bricata/mysql-dump/cmc-db.sql.gz
fi

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

%attr(0755,root,root) /usr/bin/*.sh

/var/lib/bricata/mysql-dump/cmc-db.sql.gz

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
