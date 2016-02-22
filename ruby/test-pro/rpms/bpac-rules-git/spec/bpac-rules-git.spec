
Name:           bpac-rules-git
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        2%{?dist}
Summary:        Create empty git repo for storing rules.
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

PreReq:         bpac-cmc-user
Requires:       git
Requires:       systemd

%description

Create empty git repository for sensor rules at system start.


%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

cp -a src/* "$RPM_BUILD_ROOT/"
mkdir -p "$RPM_BUILD_ROOT"/var/www/git/rules.git/

%clean
rm -rf "$RPM_BUILD_ROOT"

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

# Whole /var/www/git/ directory is mounted in docker, so whole /var/www/git/ will be clean.
%dir %attr(0755,cmc,cmc) /var/www/git/
%dir %attr(0755,cmc,cmc) /var/www/git/rules.git/

%attr(0755,cmc,cmc) /usr/bin/*.sh
/usr/lib/systemd/system/*.service

/usr/lib/tmpfiles.d/bpac-rules-git.conf

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
