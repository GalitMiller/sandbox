#!/bin/bash

check() {
  local OK_MESSAGE="${1:?Argument is required: Message to display when test pass.}"
  local FAIL_MESSAGE="${2:?Argument is required: Message to display when test fails.}"
  shift 2

  # Execute command
  if ( "$@" )
  then
    echo "OK	$OK_MESSAGE"
  else
    echo "FAIL	$FAIL_MESSAGE" >&2
    return 1
  fi

}

# Check a service. First argument is name of the service. Rest of arguments is the command to execute.
check_service() {
  local SERVICE_NAME="${1:?Argument is required: name or short description of a service to check.}"
  shift 1

  check "$SERVICE_NAME is allive." "$SERVICE_NAME is not alive." "$@"
}

# Check a "file". First argument is name of the file. Rest of arguments is the command to execute.
check_file() {
  local FILE_NAME="${1:?Argument is required: name or short description of a file to check.}"
  shift 1

  check "$FILE_NAME is found." "$FILE_NAME is not found." "$@"
}

check_systemd_service() {
  local SERVICE="${1:?Argument is required: name of systemd service to check status in docker container.}"

  check_service "Service $SERVICE" systemctl is-active --quiet "$SERVICE"
}


# Wrapper for check_http Nagios plugin.
# See https://www.monitoring-plugins.org/doc/man/check_http.html
check_http() {
  /usr/lib64/nagios/plugins/check_http -I "${CONTAINER_IP:-127.0.0.1}" --port="${APP_PORT:-5443}" -S "$@"
}
