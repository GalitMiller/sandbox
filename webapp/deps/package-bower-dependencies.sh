#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"

DEFINE_ONLY="yes"
. "$BIN_DIR"/bower2srpm.sh

bower2srpm    "angular" "1.3.15"
bower2srpm    "angular-resource" "1.3.15"
bower2srpm    "angular-route" "1.3.15"
bower2srpm    "bootstrap-sass" "3.3.3"
bower2srpm    "angular-ui-bootstrap-bower" "0.13.0"
bower2srpm    "ng-table" "0.5.4"
bower2srpm    "i18next" "1.7.7"
bower2srpm    "ng-i18next" "0.3.6"
bower2srpm    "angular-moment" "0.9.0"
bower2srpm    "ng-scrollable" "0.1.2"
bower2srpm    "angular-bootstrap-colorpicker" "3.0.13"
bower2srpm    "angular-mocks" "~1.3.14"
bower2srpm    "jasmine-jquery" "2.1.0"
bower2srpm    "jquery" "2.1.3"

bower2srpm    "moment" "2.9.0"
bower2srpm    "angular-cookies" "1.3.15"