#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
cd "$BIN_DIR"

CONTAINER_NAME="${CONTAINER_NAME:-bpac}"

run_and_test() {
  ./run.sh

  # Wait until bpac-bricata-workers service will start
  for (( I=0; $(docker exec "$CONTAINER_NAME" systemctl is-active -q bpac-bricata-workers.service >/dev/null 2>&1; echo $?; )!=0 && I<120 ; I++ ))
  do
    echo -n "."
    sleep 1
  done

  if (( I==120 )) ; then
    echo
    echo "ERROR: Some services are failed to start. Review log:" >&2
    return 1
  else
    echo "OK"
  fi

  # Run test cases
  tests/test_all.sh
}

run_and_test "$@"
