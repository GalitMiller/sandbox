#!/bin/bash
set -ue

# Import script, so it routines will be available for unit-testing.
# (This is not necessary for functional testing, of course.)
DEFINE_ONLY="yes"
SCRIPT_NAME="${0##*test-}"
. ../src/usr/bin/"$SCRIPT_NAME"

EXIT_CODE=0

# Setup
# Create temporary directory
TMP_DIR="$(mktemp -d)"
mkdir -p "$TMP_DIR"

# Sample test case
test_sample() {

  # Call main routine of script, which name is same as name of script file
  "${SCRIPT_NAME%.sh}" "$TMP_DIR/message.txt" || {
    echo "ERROR: Script finishned with non-zero exit code: $?." >&2
    return 1
  }

  # 
  [ -s "$TMP_DIR/message.txt" ] || {
    echo "ERROR: message file is not created." >&2
    return 1
  }

  local EXPECTED_CONTENT="Hello, world!"
  local ACTUAL_CONTENT="$(cat "$TMP_DIR/message.txt")"
  [ "$ACTUAL_CONTENT" == "$EXPECTED_CONTENT" ] || {
    echo "ERROR: Unexpected content of the file message.txt. Expected content: \"$EXPECTED_CONTENT\", actual content: \"$ACTUAL_CONTENT\"." >&2
    return 1
  }

  return 0
}

test_sample || EXIT_CODE=$?

# Cleanup
rm -rf "$TMP_DIR"

exit $EXIT_CODE
