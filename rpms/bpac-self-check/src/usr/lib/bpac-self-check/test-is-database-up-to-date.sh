#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

check "BPAC database version is up to date." "BPAC database version is not up to date." bash -c 'bpac-manage.sh db current 2>&1 | fgrep "(head)" >/dev/null'
