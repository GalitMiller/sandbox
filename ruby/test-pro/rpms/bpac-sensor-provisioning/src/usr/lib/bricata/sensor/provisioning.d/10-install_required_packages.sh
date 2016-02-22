#!/bin/bash
set -ue

# Script to install packages on sensor using apt-get.

SENSOR_REQUIRED_PACKAGES=( git openssh-server wcstools )

install_required_packages() {
  local PACKAGES_TO_INSTALL=( "${SENSOR_REQUIRED_PACKAGES[@]}" "${@:+$@}" )

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
    install_required_packages "${ADDITIONAL_PACKAGES_TO_INSTALL[@]:+${ADDITIONAL_PACKAGES_TO_INSTALL[@]}}"
  else
    # Get parameters from script arguments
    install_required_packages "$@"
  fi
}
