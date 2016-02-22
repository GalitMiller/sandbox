
Name:           bpac-first-boot
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Service to run script once, at first invocation.
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

PreReq:         bpac-cmc-user

Requires:       mariadb-server
Requires:       mariadb
Requires:       util-linux
Requires:       bpac-bricata

%description

Systemd service to run scripts at first boot, or at first start of the service.


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

/usr/lib/systemd/system/bpac-first-boot.service


%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
