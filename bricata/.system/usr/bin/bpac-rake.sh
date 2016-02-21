#!/bin/bash
set -ue
BRICATA_HOME="/var/www/bricata"

cd "$BRICATA_HOME" || {
  echo "ERROR: Cannot enter into \"$BRICATA_HOME\" directory. Check is directory exists and is this user has permissions to enter it." >&2
}

exec /usr/sbin/runuser -u apache -g apache -- rake "$@"
