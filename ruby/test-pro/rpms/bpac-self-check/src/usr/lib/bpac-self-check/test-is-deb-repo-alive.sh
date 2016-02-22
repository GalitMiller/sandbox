#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

check_service "BPAC deb repository" check_http -s 'Bricata ProAccel Pro' -u /repo/ubuntu/conf/distributions

check_file "bpac-ids-cmcadmin-profile deb package" check_http -s "bpac-ids-cmcadmin-profile" -u /repo/ubuntu/pool/bpac/b/bpac-ids-cmcadmin-profile/
