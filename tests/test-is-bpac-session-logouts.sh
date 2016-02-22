#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

login

check_page "/api/v1/current_user" "Administrator"

logout

check_page "/api/v1/current_user" "Unauthorized"
