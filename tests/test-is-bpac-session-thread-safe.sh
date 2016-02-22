#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

run_number_of_checks() {
  local USER="${1:?Argument is required: user login name to login into Bricata, e.g. \"bricata@bricata.com\".}"
  local PASSWORD="${2:?Argument is required: user password, e.g. \"bricata\".}"
  local USER_NAME="${3:?Argument is required: user name to check for at /apu/v1/current_user page, e.g \"Administrator\".}"
  local NUMBER_OF_CHECKS="${4:-100}" # 100 requests by default

  local HEADERS_TMP_FILE="$(mktemp /tmp/test-headers.XXXXXXXXX)" # Use our own file with cookies, to avoid clashes in case of parallel invocation
  login "$USER" "$PASSWORD"

  local I
  for((I=0; I<$NUMBER_OF_CHECKS; I++))
  do
    check_page "/api/v1/current_user" "$USER_NAME"
  done
}

docker exec "${CONTAINER_NAME:-bpac}" mysql -u root -e "INSERT INTO users VALUES ('test@test.com','\$2a\$10\$ja7aoV3N7MC.sFbAbYI9rucE1tmwKVfp1E9qRuEKAY99LmlwiXNvG',NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,0,1,0,2,45,0,'Test User','UTC',0,1,1,'2015-07-27 16:57:36','2015-07-27 16:57:36',0,'2015-07-27 16:19:08',201530,201507,NULL,0);" bricata || {
  echo "WARNING: Cannot create user test@test.com."
}

# Run checks in parallel
( run_number_of_checks "test@test.com" "testPass" "Test User" ) &
run_number_of_checks "bricata@bricata.com" "bricata" "Administrator"

wait %1
echo "FINISHED."
