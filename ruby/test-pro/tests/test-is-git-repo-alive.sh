#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

check_service "Git repository" check_http -s 'repository' -u /git/rules.git/description
