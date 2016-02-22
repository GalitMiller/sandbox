
Name:           bpac-celery
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        3%{?dist}
Summary:        Celery unit file for systemd.
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

PreReq:         bpac-cmc-user

Requires:       systemd
Requires:       python-celery

%description

Celery unit file for systemd, to run celery as system service, and it configuration file.


%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

cp -a src/* "$RPM_BUILD_ROOT/"

mkdir -p "$RPM_BUILD_ROOT"/var/lib/celery "$RPM_BUILD_ROOT"/var/log/celery

%clean
rm -rf "$RPM_BUILD_ROOT"

#%pre
## Create group and user for celery
#getent group celery >/dev/null || groupadd -r celery
#getent passwd celery >/dev/null || useradd -r -g celery -d /var/lib/celery -s /sbin/nologin -c "celery daemon user" celery

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

%config(noreplace) /etc/sysconfig/celery
/usr/lib/systemd/system/celery.service
/usr/lib/systemd/system/celerybeat.service
/usr/lib/tmpfiles.d/celery.conf

%dir %attr(755,cmc,cmc) /var/lib/celery
%dir %attr(755,cmc,cmc) /var/log/celery

/etc/logrotate.d/celery

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
