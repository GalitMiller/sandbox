
Name:           bpac-httpd-conf
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Configuration of BPAC and Bricata servers for Apache httpd
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

Requires:       httpd
# For python backend
Requires:       mod_wsgi
# For ruby backend
Requires:       mod_passenger
# For https
Requires:       mod_ssl


%description

Configuration file for Apache httpd with configuration for WSGI and Passenger modules for BPAC and Bricata(Suricata) servers.

%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

cp -a src/* "$RPM_BUILD_ROOT/"

%post
# Delete default ssl server from ssl.conf
sed -i '/## SSL Virtual Host Context/,$d' /etc/httpd/conf.d/ssl.conf

# Comment out Listen directives so they will not conflict with Listen directives in bpac.conf
sed -i 's/^Listen/#Listen/' /etc/httpd/conf.d/ssl.conf /etc/httpd/conf/httpd.conf

%clean
rm -rf "$RPM_BUILD_ROOT"

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

%config /etc/httpd/conf.d/bpac.conf

/usr/lib/tmpfiles.d/bpac-httpd-conf.conf
/var/www/.htpasswd
/var/www/run/.gitignore

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
