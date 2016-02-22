#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
. "$BIN_DIR"/common.sh

check "MySQL service is accessibe with predefined password bricata/br1c@t@ (which is good for development but is the security hole in production)." \
      "MySQL service is not accessibe with predefined password bricata/br1c@t@ (which is bad for development but closes security hole in production)." \
      mysql -h 127.0.0.1 -u bricata --password='br1c@t@' -e 'show databases;'

check "MySQL service is accessibe with predefined password root/bricata (which is good for development but is the security hole in production)." \
      "MySQL service is not accessibe with predefined password root/bricata (which is bad for development but closes security hole in production)." \
      mysql -h 127.0.0.1 -u root --password='bricata' -e 'show databases;'

