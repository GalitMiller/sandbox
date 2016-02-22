#!/bin/bash

# When bricata or bpac application is contacted, it must respond with
# Set-Cookie header with expiration date set to +15 minutes from now.

set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh


SESSION_TIMEOUT="$((15*60))" # 15 minutes

HEADERS_TMP_FILE="/tmp/headers"
PREV_COOKIE_TIMEOUT=0

date_to_seconds() {
  date --date="${1:?Argument required: date to convert.}" +%s
}

check_cookie_timeout() {
  local HEADERS_TMP_FILE="${1:?Argument required: path to file with headers with cookies.}"

  local EXPIRES_AT="$(cat "$HEADERS_TMP_FILE" | grep -i 'Set-Cookie: _bricata_session=' | grep -ioE 'expires=[^;]*;' | cut -d '=' -f 2 | tr -d ';')"
  local EXPIRES_AT_IN_SECONDS="$(date_to_seconds "$EXPIRES_AT")"
  local NOW="$(date +%s)"
  local COOKIE_TIMEOUT=$((EXPIRES_AT_IN_SECONDS - NOW))

  #cat "$HEADERS_TMP_FILE"
  #echo "DEBUG: EXPIRES_AT=$EXPIRES_AT, SESSION_TIMEOUT=$SESSION_TIMEOUT, COOKIE_TIMEOUT=$COOKIE_TIMEOUT, page: $*."

  if (( COOKIE_TIMEOUT < 0 ))
  then
    echo "ERROR: _bricata_session is not set or cookie has no expires= option." >&2
    cat "$HEADERS_TMP_FILE"
  fi

  if (( SESSION_TIMEOUT < COOKIE_TIMEOUT ))
  then
    cat "$HEADERS_TMP_FILE"
    echo "ERROR: session must end in 15 minutes after last request to $*." >&2
    exit 1
  fi

  if (( PREV_COOKIE_TIMEOUT > 0 && PREV_COOKIE_TIMEOUT+1 < COOKIE_TIMEOUT ))
  then
    cat "$HEADERS_TMP_FILE"
    echo "ERROR: session time must be extended to be at least 15 minutes after last request to $*." >&2
    exit 1
  fi

  let PREV_COOKIE_TIMEOUT=COOKIE_TIMEOUT
}


# Login into bricata, store server response headers. Cookie expiration time must be set to about +15 minutes from now.
curl -sk "https://${CONTAINER_IP:-127.0.0.1}/users/login" \
     --dump-header "$HEADERS_TMP_FILE" \
     --data 'utf8=%E2%9C%93&authenticity_token=XyVrRozSpFG94nIFcIE7Zs3ODtqRHDCSYkfk%2BMkniGU%3D&user%5Bemail%5D=bricata%40bricata.com&user%5Bpassword%5D=bricata&user%5Bremember_me%5D=0&user%5Bremember_me%5D=1' >/dev/null
check_cookie_timeout "$HEADERS_TMP_FILE" "login page"


# Sleep for 3s and contact bricata: cookie expiration time must be larger than previous, while still <=15m from now.
sleep 3
curl -sk "https://${CONTAINER_IP:-127.0.0.1}/dashboard" --cookie "$HEADERS_TMP_FILE" --dump-header "$HEADERS_TMP_FILE.2" >/dev/null
check_cookie_timeout "$HEADERS_TMP_FILE.2" "dashboard page"

# Contact bpac: cookie expiration time must be larger than previous, while still <=15m from now.
sleep 3
curl -sk "https://${CONTAINER_IP:-127.0.0.1}/api/v1/current_user" --cookie "$HEADERS_TMP_FILE" --dump-header "$HEADERS_TMP_FILE.3" >/dev/null
check_cookie_timeout "$HEADERS_TMP_FILE.3" "BPAC API"

rm -rf "$HEADERS_TMP_FILE"*
