#!/bin/bash
set -ue

BPAC_HOME="/var/www/app"

cd "$BPAC_HOME" || {
  echo "ERROR: Cannot enter into \"$BPAC_HOME\" directory. Check is directory exists and is this user has permissions to enter it." >&2
}

exec /usr/sbin/runuser -u cmc -g cmc -- ./manage.py "$@"
