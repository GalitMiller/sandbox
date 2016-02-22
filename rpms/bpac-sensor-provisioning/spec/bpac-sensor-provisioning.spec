
Name:           bpac-sensor-provisioning
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Sensor provisioning package
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

Requires:       openssh-clients

%description

Scripts to setup Bricata sensor.


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

%dir /etc/bricata/sensor-provisioning.d/
%config(noreplace) /etc/bricata/sensor-provisioning.d/*.*


%dir /usr/lib/bricata/sensor/provisioning.d/
%attr(0755,root,root) /usr/lib/bricata/sensor/provisioning.d/*.sh
%attr(0755,root,root) /usr/bin/*.sh

%changelog
* Tue May 05 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
