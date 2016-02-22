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
  local CONTAINER_NAME="${CONTAINER_NAME:-bpac}"

  check_service "Service $SERVICE" docker exec "$CONTAINER_NAME" systemctl is-active --quiet "$SERVICE"
}


# Wrapper for check_http Nagios plugin.
# See https://www.monitoring-plugins.org/doc/man/check_http.html
check_http() {
  /usr/lib64/nagios/plugins/check_http -I "${CONTAINER_IP:-127.0.0.1}" -S "$@"
}

# Execute command and then try to find substring in command output.
match_string() {
  local STRING="${1:?Argument is required: string to find in output of a command.}"
  shift

  "$@" | fgrep -q "$STRING"
}

# Temporary file to keep cookie
HEADERS_TMP_FILE="$(mktemp /tmp/test-headers.XXXXXXXXX)"

# Login into bricata using demo account (will NOT work in production),
# and store cookie in HEADERS_TMP_FILE.
login() {
  local USER="${1:-bricata@bricata.com}"
  local PASSWORD="${2:-bricata}"
  check "Can login into Bricata server using account \"$USER\"." \
        "Cannot login into Bricata server using account \"$USER\" and password \"$PASSWORD\"." \
        match_string '"success":true' \
          curl_with_cookie \
            -sk "https://${CONTAINER_IP:-127.0.0.1}/users/login" \
            --data "utf8=%E2%9C%93&authenticity_token=XyVrRozSpFG94nIFcIE7Zs3ODtqRHDCSYkfk%2BMkniGU%3D&user%5Bemail%5D=$USER&user%5Bpassword%5D=$PASSWORD&user%5Bremember_me%5D=0&user%5Bremember_me%5D=1"

  # Remove temporary file at exit
  trap "rm -f '$HEADERS_TMP_FILE'" EXIT
}

# Logout from application
logout() {
  check "Can logout from Bricata." \
        "Cannot logout from Bricata." \
        match_string 'redirected' \
          curl_with_cookie \
            -sk "https://${CONTAINER_IP:-127.0.0.1}/users/logout"
}

curl_with_cookie() {
  curl --cookie-jar "$HEADERS_TMP_FILE" --cookie "$HEADERS_TMP_FILE" "$@"

  #echo "DEBUG: Cookies after visiting of $*: $(cat "$HEADERS_TMP_FILE")" >&2
}

# Check page of application with cookie (logged in).
check_page() {
  local PAGE="${1:?Argument is required: path to page.}"
  local STRING="${2:?Argument is required: substring to find in page contentn.}"

  check \
    "Page \"$PAGE\" is alive." \
    "Page \"$PAGE\" is not alive." \
    match_string "$STRING" \
      curl_with_cookie -sk "https://${CONTAINER_IP:-127.0.0.1}/$PAGE"
}
