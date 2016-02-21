#!/bin/bash
set -ue

# Create tar.gz archives from directories to build RPM packages from them using "tar build" method.

make_tar_archive_of_dir() {
  local SOURCE_DIR="${1:?Argument required: path to source directory to make archive from.}"
  local TARGET_DIR="${2:?Argument required: path to target directory to store archives into, e.g. \"/tmp/packages\".}"
  local PACKAGE_NAME="${3:?Argument required: package name.}"

  mkdir -p "$TARGET_DIR" || {
    echo "ERROR: Cannot create directory: $TARGET_DIR." >&2
    return 1
  }

  # Make tar archive.
  local SPEC_FILE="$SOURCE_DIR/spec/$PACKAGE_NAME.spec"
  # Sanity checks
  [ -e "$SPEC_FILE" ] || {
    echo "ERROR: No spec file is found in \"$SOURCE_DIR\" directory. Script expects ./spec/PACKAGE_NAME.spec layout." >&2
    return 1
  }
  [ -s "$SPEC_FILE" ] || {
    echo "ERROR: Empty spec file \"$SPEC_FILE\". RPM will not build RPM package out of it." >&2
    return 1
  }

  echo "INFO: Storing changelog for \"$PACKAGE_NAME\" package using command \"git log --oneline -- $SOURCE_DIR\"."
  mv -f "$SOURCE_DIR/Changelog" "$SOURCE_DIR/Changelog.orig"
  git log --oneline -- "$SOURCE_DIR" > "$SOURCE_DIR/Changelog" || : # Ignore errors

  echo "INFO: Making archive \"$TARGET_DIR/$PACKAGE_NAME.tar.gz\" from \"$SOURCE_DIR/\" directory."
  tar czf "$TARGET_DIR/$PACKAGE_NAME.tar.gz" -C "$SOURCE_DIR/.." "$(basename "$SOURCE_DIR")" || {
    echo "ERROR: Cannot create tar.gz archive \"$TARGET_DIR/$PACKAGE_NAME.tar.gz\" from \"$SOURCE_DIR\" directory." >&2
    # Restore original changelog file
    mv -f "$SOURCE_DIR/Changelog.orig" "$SOURCE_DIR/Changelog"
    return 1
  }

  # Restore original changelog file
  mv -f "$SOURCE_DIR/Changelog.orig" "$SOURCE_DIR/Changelog"

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  make_tar_archive_of_dir "$@"
}
