#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

check_service "Static directory" check_http -s 'BPAC' -u /static/VERSION.txt
