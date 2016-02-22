#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

check_service "BPAC backend" check_http -e 401 -u /api/v1/current_user
