#!/bin/bash
set -ue

# Script to install BPAC packages on sensor using apt-get.
# This module can be executed only after BPAC APT repository was enabled

SENSOR_BPAC_PACKAGES=( bpac-ids-ifnet-info bpac-ids-pull-rules bpac-ids-cmcadmin-profile )

install_bpac_packages() {
  local PACKAGES_TO_INSTALL=( "${SENSOR_BPAC_PACKAGES[@]}" "${@:+$@}" )

  apt-get install -y "${PACKAGES_TO_INSTALL[@]}" \
  || {
    echo "ERROR: Cannot install packages using apt-get." >&2
    return 1
  }

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  if [ "${CONFIG_MODE:-}" == "yes" ] ; then
    # Get parameters from environment variables when in CONFIG_MODE
    install_bpac_packages "${ADDITIONAL_BPAC_PACKAGES_TO_INSTALL[@]:+${ADDITIONAL_BPAC_PACKAGES_TO_INSTALL[@]}}"
  else
    # Get parameters from script arguments
    install_bpac_packages "$@"
  fi
}
