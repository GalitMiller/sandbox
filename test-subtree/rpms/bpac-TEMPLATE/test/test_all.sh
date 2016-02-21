#!/bin/bash
BIN_DIR="$(dirname "$0")"
EXIT_CODE=0

for I in "$BIN_DIR"/test-*.sh
do
  TEST_CASE_OUTPUT="$( "$I" 2>&1 )" || {
    EXIT_CODE=$?
    echo "ERROR: Test case \"$I\" failed." >&2
    echo >&2
    echo "$TEST_CASE_OUTPUT" >&2
    echo >&2
    continue
  }
  echo -n "."
done
echo


exit $EXIT_CODE
