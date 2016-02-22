
Name:           bpac-cmc-user
Version:        %{?bpacver}%{!?bpacver:1.0}%{?gitver}
Release:        1%{?dist}
Summary:        Create cmc user and generate ssh key pair
Group:          bricata
License:        Other/Proprietary
URL:            http://www.bricata.com/
Source:         %{name}.tar.gz
BuildArch:      noarch

%description

Create cmc user and generate key pair for SSH.

NOTE: by now, just deliver pre-generated key, so key will not change often during development.

%prep
%setup -n %{name}

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"

cp -a src/* "$RPM_BUILD_ROOT/"

%pre
# Create group and user for CMC
getent group cmc >/dev/null || groupadd cmc
getent passwd cmc >/dev/null || useradd -g cmc -c "CMC user" cmc

%post
[ -s /home/cmc/.ssh/id_rsa ] || runuser -u cmc ssh-keygen -q -N '' -f /home/cmc/.ssh/id_rsa

cat <<CMC_PUB_KEY_CONFIG_FILE >/etc/bricata/sensor-provisioning.d/cmc_public_key.sh
# Public key(s) of CMC to use for cmc user at sensors, so sensor will allow to log in.
CMC_PUBLIC_KEYS=( 
  '$(cat /home/cmc/.ssh/id_rsa.pub)'
)
CMC_PUB_KEY_CONFIG_FILE

[ -s /var/www/app/ssh/sensor.key ] || {
  mkdir -p /var/www/app/ssh/
  cp -f /home/cmc/.ssh/id_rsa /var/www/app/ssh/sensor.key
  chmod -R 0500 /var/www/app/ssh/
  chown -R cmc.cmc /var/www/app/ssh/
}


%clean
rm -rf "$RPM_BUILD_ROOT"

%files
%defattr(0644,root,root,755)
%doc README.md Changelog

# FIXME: To generate key automatically, delete this file from spec and file system.
%dir %attr(0500,cmc,cmc) /home/cmc/.ssh
%attr(0400,cmc,cmc) /home/cmc/.ssh/*
# Copy of private key for use in python code
%dir %attr(0500,cmc,cmc) /var/www/app/ssh
%attr(0400,cmc,cmc) /var/www/app/ssh/sensor.key

%config(noreplace) %{_sysconfdir}/bricata/sensor-provisioning.d/cmc_public_key.sh
%config	%{_sysconfdir}/profile.d/bricata_cmc.sh

# Git configuration file for cmc
%config(noreplace) %attr(0640,cmc,cmc) /home/cmc/.gitconfig

%changelog
* Thu May 07 2015 Volodymyr M. Lisivka <vlisivka@softserveinc.com> - 1.0-1
- Initial version.
