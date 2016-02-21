#!/bin/bash
set -ue

# Create yum repository in directory with RPM packages.

make_yum_repository() {
  local PACKAGES_DIR="${1:?Argument required: path to directory with RPM packages to build yum repository.}"

  # Sanity checks
  [ -d "$PACKAGES_DIR" ] || {
    echo "ERROR: Not a directory: \"$PACKAGES_DIR\". Cannot make yum repository here. It must be an existing directory with binary RPM packages." >&2
    return 1
  }
  (( $(ls "$PACKAGES_DIR"/*.rpm | wc -l) > 0 )) || {
    echo "ERROR: No RPM packages in \"$PACKAGES_DIR\". Cannot make yum repository here. It must be an existing directory with binary RPM packages." >&2
    return 1
  }

  (( $(which createrepo_c | wc -l) > 0 )) || {
    echo "ERROR: Package createrepo_c is not installed. Cannot generate yum repository." >&2
    return 1
  }

  echo "INFO: Making yum repository in \"$PACKAGES_DIR\"."
  local OUTPUT
  OUTPUT="$( createrepo_c "$PACKAGES_DIR" 2>&1)" || {
    echo "ERROR: Cannot create yum repository in \"$PACKAGES_DIR\"." >&2
    echo >&2
    echo "$OUTPUT" >&2
    echo
    return 1
  }

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {
  make_yum_repository "$@"
}
