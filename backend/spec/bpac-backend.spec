
Name:           bpac-backend
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        BPAC backend written in Python
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

BuildRequires:  python2 > 2.7

BuildRequires:  python-coverage
BuildRequires:  python-freezegun
BuildRequires:  python-mock
BuildRequires:  python-nose
BuildRequires:  python-nose-exclude
BuildRequires:  python-invoke
BuildRequires:  python-dateutil
BuildRequires:  python-mimerender
BuildRequires:  python-tempita
BuildRequires:  python-decorator
BuildRequires:  python-sqlparse

# TODO: remove requirements which are not required for building and testing
BuildRequires:  python-flask-restless >= 0.17.1dev
BuildRequires:  python-flask >= 0:0.10.1
BuildRequires:  python-flask-cache >= 0.13.1
BuildRequires:  python-flask-celery-helper >= 1.1.0
BuildRequires:  python-flask-login >= 0.2.11
BuildRequires:  python-flask-sqlalchemy >= 2.0
BuildRequires:  python-flask-migrate >= 1.4.0
BuildRequires:  MySQL-python >= 1.2.5
BuildRequires:  python-sqlalchemy >= 0.9.9
BuildRequires:  python-sqlalchemy-continuum >= 1.1.5
BuildRequires:  python-sqlalchemy-utils >= 0.30.0
BuildRequires:  python-awesome-slugify >= 1.6.4
BuildRequires:  python-celery >= 3.1.17
BuildRequires:  python-colour >= 0.1.1
BuildRequires:  GitPython >= 1.0.1
BuildRequires:  python-inflection >= 0.3.1
BuildRequires:  python-isotopic-logging >= 1.0.1
BuildRequires:  python-logsna >= 1.2
BuildRequires:  python-netifaces >= 0.10.4
BuildRequires:  python-paramiko >= 1.15.2
BuildRequires:  python-pyasn1 >= 0.1.7
BuildRequires:  python-redis >= 2.10.3
BuildRequires:  python-schematics >= 1.0.4
BuildRequires:  python-scp >= 0.10.0
BuildRequires:  python-superdict >= 1.0.3
BuildRequires:  python-twisted >= 15.1.0
BuildRequires:  python-unipath >= 1.1
BuildRequires:  bpython >= 0.13
BuildRequires:  python-flask-script >= 2.0.5
BuildRequires:  pylint >= 1.4.3
BuildRequires:  python-alembic >= 0.7.4
BuildRequires:  python-ujson >= 1.33
BuildRequires:  python-funcy >= 1.5
BuildRequires:  python-py >= 1.4.17
BuildRequires:  python-whatever >= 0.4.1
BuildRequires:  python-fake-factory >= 0.5.2
BuildRequires:  python-factory-boy >= 2.5.2

PreReq:         bpac-cmc-user

Requires:       logrotate
Requires:       util-linux
Requires:       python2 > 2.7

# TODO: remove dependencies which are required for testing only

# python-flask-restless is patched
Requires:       python-flask-restless >= 0.17.1dev

Requires:       python-flask >= 0.10.1
Requires:       python-flask-cache >= 0.13.1
Requires:       python-flask-celery-helper >= 1.1.0
Requires:       python-flask-login >= 0.2.11
Requires:       python-flask-sqlalchemy >= 2.0
Requires:       python-flask-migrate >= 1.4.0
Requires:       MySQL-python >= 1.2.5
Requires:       python-sqlalchemy >= 0.9.9
Requires:       python-sqlalchemy-continuum >= 1.1.5
Requires:       python-sqlalchemy-utils >= 0.30.0
#Requires:       python-sqlalchemy-migrate >= 0.9.6 # See BPAC-789
Requires:       python-awesome-slugify >= 1.6.4
Requires:       python-celery >= 3.1.17
Requires:       python-colour >= 0.1.1
Requires:       GitPython >= 1.0.1
Requires:       python-inflection >= 0.3.1
Requires:       python-isotopic-logging >= 1.0.1
Requires:       python-logsna >= 1.2
Requires:       python-netifaces >= 0.10.4
Requires:       python-paramiko >= 1.15.2
Requires:       python-pyasn1 >= 0.1.7
Requires:       python-redis >= 2.10.3
Requires:       python-schematics >= 1.0.4
Requires:       python-scp >= 0.10.0
Requires:       python-superdict >= 1.0.3
Requires:       python-twisted >= 15.1.0
Requires:       python-unipath >= 1.1
Requires:       bpython >= 0.13
Requires:       python-flask-script >= 2.0.5
Requires:       pylint >= 1.4.3
Requires:       python-gitdb >= 0.6.4
Requires:       python-alembic >= 0.7.4
Requires:       python-ujson >= 1.33
Requires:	python-funcy >= 1.5
Requires:	python-py >= 1.4.17
Requires:	python-whatever >= 0.4.1
Requires:	python-fake-factory >= 0.5.2
Requires:	python-factory-boy >= 2.5.2


Requires:       python-dateutil
Requires:       python-mimerender
Requires:       python-tempita
Requires:       python-decorator
Requires:       python-sqlparse


%description

Backend for BPAC application.


%prep
%setup -n backend

%build

# Remove *.pyc *.pyo and vritual environment (if any)
make dist-clean

# Compile python files
find . -name '*.py' -type f -exec python -m py_compile '{}' '+'

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

mkdir -p "$RPM_BUILD_ROOT/var/www/app/"
cp -a app/ migrations/ manage.py* bpac.wsgi "$RPM_BUILD_ROOT/var/www/app/"

mkdir -p "$RPM_BUILD_ROOT/"
cp -a .system/* "$RPM_BUILD_ROOT/"


mkdir -p "$RPM_BUILD_ROOT"/var/log/bpac
rm -rf "$RPM_BUILD_ROOT"/var/www/app/logs
ln -sf /var/log/bpac "$RPM_BUILD_ROOT"/var/www/app/logs

# Patch app/core/views/api.py to put API at /v1/... instead of /api/v1/..., because in apache configuration it will be mounted at /api instead of /.
sed -i -e 's/\/api\/v/\/v/' "$RPM_BUILD_ROOT"/var/www/app/app/core/views/api.py

%clean
rm -rf "$RPM_BUILD_ROOT"

%check
make test

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

%attr(0755,root,root) /usr/bin/*.sh
%dir /var/www/app
/var/www/app/app
/var/www/app/migrations

%attr(755,root,root) /var/www/app/manage.py*
/var/www/app/bpac.wsgi

%dir %attr(755,cmc,cmc) /var/log/bpac

# Symlink only
/var/www/app/logs

/etc/logrotate.d/bpac

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
