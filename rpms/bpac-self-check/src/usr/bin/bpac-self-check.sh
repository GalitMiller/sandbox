#!/bin/bash

check_all() {
  local EXIT_CODE=0
  local SERVICES_TO_SHOW_LOGS=( )

  local I
  for I in "$@"
  do
    [ -s "$I" ] || continue # Skip non-files

    local TEST_CASE_NAME="${I##*/}" # Strip path to file
    TEST_CASE_NAME="${TEST_CASE_NAME%.sh}" # Strip .sh suffix

    # Execute test and store it output to display it only in case of failure (unless VERBOSE is set to "yes").
    local TEST_CASE_OUTPUT
    TEST_CASE_OUTPUT="$( "$I" 2>&1 )" || {
      EXIT_CODE=$?
      echo "ERROR:	Test case \"$TEST_CASE_NAME\" failed." >&2
      echo 'vvvvvvvvvvvvvvvvvvvvvvvvvv' >&2
      echo "$TEST_CASE_OUTPUT" >&2
      echo '^^^^^^^^^^^^^^^^^^^^^^^^^^' >&2

      # Failure of test case may be cause by a problem in one of depended services, so store names of these services in the array
      SERVICES_TO_SHOW_LOGS=( "${SERVICES_TO_SHOW_LOGS[@]:-}" $(cat "$I.deps" || :)  )
      continue
    }

    echo "OK	Test case \"$TEST_CASE_NAME\" passed."
    # Display output of test case when VERBOSE is set to "yes".
    [ "${VERBOSE:-no}" != "yes" ] || {
      echo 'vvvvvvvvvvvvvvvvvvvvvvvvvv'
      echo "$TEST_CASE_OUTPUT"
      echo '^^^^^^^^^^^^^^^^^^^^^^^^^^'
    }
  done

  # If some test cases are failed
  if (( ${#SERVICES_TO_SHOW_LOGS[@]} > 0 ))
  then
    # Show logs for services which are might fail or contains information about failure
    bpac-show-logs.sh "${SERVICES_TO_SHOW_LOGS[@]:-}"
  fi

  return $EXIT_CODE
}

check_all /usr/lib/bpac-self-check/test-*.sh
