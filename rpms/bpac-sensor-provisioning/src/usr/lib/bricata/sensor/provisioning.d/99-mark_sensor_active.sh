#!/bin/bash
set -ue

#
# This module will mark the sensor as 'activated' by creating a file on the filesystem.
# This 'label' will be needed for futher tools and modules.
# This module should run as the latest in the sensor activation chain.


# Creates a file on sensor's filesystem to mark that it is controlled by CMC
# Argument 1 or variable CMC_IP: IP of CMC. Required.
# Variables:
#  SENSOR_ACT_FILE - File that plays a role of activation label. Default: /etc/sensor-activated-by-cmc
function mark_sensor_active() {
  local CMC_IP="${1:?Argument is required: IP address of CMC host.}"

  local SENSOR_ACT_FILE="${SENSOR_ACT_FILE:-/etc/sensor-activated-by-cmc}"

  echo "Marking sensor as activated in file $SENSOR_ACT_FILE ..."

  # Write the file with a date in it
  sh -c "date +\"%Y%m%d-%H%M%S\" > \"$SENSOR_ACT_FILE\""
  sh -c "echo \"$CMC_IP\" >> \"$SENSOR_ACT_FILE\""

  echo "Sensor activation completed!"

  return 0
}


# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  if [ "${CONFIG_MODE:-}" == "yes" ] ; then
    # Get parameters from environment variables when in CONFIG_MODE
    mark_sensor_active "${CMC_IP:?Variable is required: CMC_IP: IP address of CMC host.}"
  else
    # Get parameters from script arguments
    mark_sensor_active "$@"
  fi
}
