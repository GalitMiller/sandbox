#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

check_service "BPAC frontend application" check_http -s 'Bricata' -u /static/index.html

check_service "BPAC frontend application main.js" check_http -s 'BPACApp' -u /static/js/main.js

check_service "BPAC frontend application angular.min.js" check_http -s 'AngularJS' -u /static/vendor/js/angular.min.js
