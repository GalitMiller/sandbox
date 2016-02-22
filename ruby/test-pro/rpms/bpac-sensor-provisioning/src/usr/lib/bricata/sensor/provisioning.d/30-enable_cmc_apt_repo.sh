#!/bin/bash
set -ue

# Installs APT repository hosted at CMC so the sensor will start receiving software packages from CMC.
# Argument 1 or variable CMC_IP: IP of CMC. Required.
# Variables:
#  SENSOR_OS_DIST - Debian-based Linux distro. Default: ubuntu
#  SENSOR_OS_REL  - Sensor OS release. Default: trusty
#  SENSOR_APT_COMP - Component in APT repository where the packages are placed. Default: bpac
#  SENSOR_APT_LIST - Filename where BPAC repository definition is stored. Default: /etc/apt/sources.list.d/bpac.list
#  CMC_SSL_PORT - CMC's SSL port. Default: 443


function enable_cmc_apt_repo() {
  local CMC_IP="${1:?Argument is required: IP address of CMC host.}"
  local CURRENT_CMC_IP=$(grep -e "cmc" "/etc/hosts"|awk '{print $1}')

  local SENSOR_OS_DIST="${SENSOR_OS_DIST:-ubuntu}"
  local SENSOR_OS_REL="${SENSOR_OS_REL:-trusty}"
  local SENSOR_APT_COMP="${SENSOR_APT_COMP:-bpac}"
  local SENSOR_APT_LIST="${SENSOR_APT_LIST:-/etc/apt/sources.list.d/bpac.list}"

  local CMC_SSL_PORT="${CMC_SSL_PORT:-443}"

  # Install APT source from CMC
  sh -c  "echo \"deb https://$CURRENT_CMC_IP/repo/$SENSOR_OS_DIST $SENSOR_OS_REL $SENSOR_APT_COMP\" > \"$SENSOR_APT_LIST\""

  # Install GPG key
  wget --no-check-certificate -O - https://$CURRENT_CMC_IP/repo/$SENSOR_OS_DIST/bpac.gpg.key | apt-key add -

  # Trust to CMC's self-signed certificate
  echo -n | openssl s_client -connect $CURRENT_CMC_IP:$CMC_SSL_PORT | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | tee '/usr/local/share/ca-certificates/bpac-ca.crt'
  update-ca-certificates || {
    echo "ERROR: Unable to add self-signed ProAccel CMC SSL certificate to Trusted Certificates Repository"
    return 1
  }

  # Set APT to not to check the hostname against SSL certificate
  echo "Acquire::https::$CURRENT_CMC_IP::Verify-Host \"false\"; Acquire::https::$CURRENT_CMC_IP::Verify-Peer \"false\";" > /etc/apt/apt.conf.d/99bpac-noverify

  # Update source metadata
  apt-get update || {
    echo "ERROR: APT was unable to update the repositories. Check if the box has proper network connection to the source server(s)"
    return 1
  }

  return 0
}


# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  if [ "${CONFIG_MODE:-}" == "yes" ] ; then
    # Get parameters from environment variables when in CONFIG_MODE
    enable_cmc_apt_repo "${CMC_IP:?Variable is required: CMC_IP: IP address of CMC host.}"
  else
    # Get parameters from script arguments
    enable_cmc_apt_repo "$@"
  fi
}

