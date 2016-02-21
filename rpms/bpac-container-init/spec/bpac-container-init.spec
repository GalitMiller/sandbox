
Name:           bpac-container-init
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Script to start container systemd daemon
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

PreReq:         systemd
PreReq:         systemd-libs
Requires:       dbus

%description

Script to start container systemd daemon.


%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

cp -a src/* "$RPM_BUILD_ROOT/"

%clean
rm -rf "$RPM_BUILD_ROOT"

%post

# Mask (create override which points to /dev/null) system services, which
# cannot be started in container anyway.
systemctl mask \
    dev-mqueue.mount \
    dev-hugepages.mount \
    remote-fs.target \
    systemd-remount-fs.service \
    sys-kernel-config.mount \
    sys-kernel-debug.mount \
    sys-fs-fuse-connections.mount \
    systemd-ask-password-wall.path \
    systemd-readahead-collect.service \
    systemd-readahead-replay.service \
    systemd-sysctl.service \
    display-manager.service \
    systemd-logind.service \
    network.service \
    getty.service


%files
%defattr(0644,root,root,755)
%doc README.md Changelog

%attr(0755,root,root) /usr/bin/*.sh

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
