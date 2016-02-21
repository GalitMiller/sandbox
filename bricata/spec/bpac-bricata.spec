
Name:           bpac-bricata
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Bricata (rebranded Snorby) package
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch


Requires:   logrotate
Requires:   wkhtmltox
Requires:   httpd
Requires:   mod_ssl
Requires:   passenger
Requires:   mod_passenger

### Ruby meta package
Requires:   bpac-meta-ruby

%description

Bricata (rebranded Snorby) package

%prep
%setup -n bricata

%install
rm -rf "$RPM_BUILD_ROOT"

mkdir -p "$RPM_BUILD_ROOT"/var/www/bricata

# Create symlink from /usr/local/src/bricata to /var/www/bricata for backward compatibility
mkdir -p "$RPM_BUILD_ROOT"/usr/local/src/
ln -sf /var/www/bricata "$RPM_BUILD_ROOT"/usr/local/src/bricata

cp -a * "$RPM_BUILD_ROOT"/var/www/bricata

cp -a .system/* "$RPM_BUILD_ROOT"/

# Create log directory and create symlink from bricata home directory to log directory
mkdir -p "$RPM_BUILD_ROOT"/var/log/bricata/
ln -sf /var/log/bricata/ "$RPM_BUILD_ROOT"/var/www/bricata/log

# Create log directory and create symlink from bricata home directory to log directory
mkdir -p "$RPM_BUILD_ROOT"/var/log/bricata/
ln -sf /var/log/bricata/ "$RPM_BUILD_ROOT"/var/www/bricata/log

# Move tmp directory to /var/run/bricata
mkdir -p "$RPM_BUILD_ROOT"/var/run/bricata/
rm -rf "$RPM_BUILD_ROOT"/var/www/bricata/tmp
ln -sf /var/run/bricata/ "$RPM_BUILD_ROOT"/var/www/bricata/tmp

# Create version file for Bricata part
cat <<VERSION_INFO > "$RPM_BUILD_ROOT"/var/www/bricata/lib/bricata/version.rb
module Bricata
  # Bricata Version
  VERSION = '%{?bpacver}%{!?bpacver:1.0}'
end
VERSION_INFO

%clean
rm -rf "$RPM_BUILD_ROOT"

%files
# FIXME: grant permissions to all files to root, grant permissions for apache user for selected files/directories only
%defattr(0644,root,root,755)
%doc README.md Changelog

/etc/logrotate.d/bricata

# Snorby application. Needs to be owned by apache user because bricata-workers service is ran by apache user and needs to write to some files.
# TODO: FIXME: avoid need to write or gran permissions to selected files only.
%attr(-,apache,apache) /var/www/bricata

# Scripts needs executable permission
%attr(0755,root,root) /var/www/bricata/script/*

# Log files
%dir %attr(0755,apache,apache) /var/log/bricata/

# Pid file for bricata workers
%dir %attr(0755,apache,apache) /var/run/bricata/

# Helper script to run rake using apache user
%attr(0755,root,root) /usr/bin/bpac-rake.sh

# Symlink
/usr/local/src/bricata

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
