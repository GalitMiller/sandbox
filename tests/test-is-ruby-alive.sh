#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

# First, check it with large timeout of 120 seconds (for first run)
check_service "Bricata login page" check_http -s 'Bricata' -u /users/login --timeout=120

# Second, check it with default timeout (10 seconds)
check_service "Bricata login page" check_http -s 'Bricata' -u /users/login

# Add event to check is dashboard working with unknown signatures (see BPAC-817).
#docker exec bpac mysql bricata -e "DELETE FROM event;"
#docker exec bpac mysql bricata -e "INSERT INTO event VALUES (1,1,1,NULL,0,NULL,0,1,0,'2015-06-25 14:49:18',1);" || :

login

check_page "/" "Bricata"
check_page "/dashboard" "Bricata"
