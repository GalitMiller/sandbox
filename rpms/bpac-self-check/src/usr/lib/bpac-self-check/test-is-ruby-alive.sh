#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh


# First, check it with large timeout of 120 seconds (for first run)
check_service "Bricata login page" check_http -s 'Bricata' -u /users/login --timeout=120

# Second, check it with default timeout (10 seconds)
check_service "Bricata login page" check_http -s 'Bricata' -u /users/login
