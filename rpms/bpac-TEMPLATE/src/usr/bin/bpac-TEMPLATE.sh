#!/bin/sh
set -ue

TEMPLATE() {
  # Print message to file or to stdout, by default.
  local  FILENAME="${1:-/dev/stdout}"

  echo "Hello, world!" >"$FILENAME"

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  if [ "${CONFIG_MODE:-}" == "yes" ] ; then
    # Get parameters from environment variables when in CONFIG_MODE
    TEMPLATE "${HELLOWORLD_MESSAGE_FILENAME:?Variable is required: HELLOWORLD_MESSAGE_FILENAME: path to file to store message in.}"
  else
    # Get parameters from script arguments
    TEMPLATE "$@"
  fi
}
