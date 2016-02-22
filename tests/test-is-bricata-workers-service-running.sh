#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

check_systemd_service bpac-bricata-workers
