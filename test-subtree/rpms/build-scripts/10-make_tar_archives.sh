#!/bin/bash
set -ue

# Create tar.gz archives from directories to build RPM packages from them using "tar build" method.

make_tar_archives() {
  local SOURCE_DIR="${1:?Argument required: path to source directory to make archives from.}"
  local TARGET_DIR="${2:?Argument required: path to target directory to store archives into, e.g. \"/tmp/packages\".}"

  mkdir -p "$TARGET_DIR" || {
    echo "ERROR: Cannot create directory: $TARGET_DIR." >&2
    return 1
  }

  # For each directory with .spec file, make tar archive.
  local SPEC_FILE
  for SPEC_FILE in "$SOURCE_DIR"/*/spec/*.spec
  do
    # Sanity checks
    [ -e "$SPEC_FILE" ] || {
      echo "ERROR: No package directories with spec files are found in \"$SOURCE_DIR\" directory. Script expects ./PACKAGE_NAME/spec/PACKAGE_NAME.spec layout." >&2
      return 1
    }
    [ -s "$SPEC_FILE" ] || {
      echo "ERROR: Empty spec file \"$SPEC_FILE\". RPM will not build RPM package out of it." >&2
      return 1
    }

    local PACKAGE_DIR="${SPEC_FILE%/spec/*}"
    local PACKAGE_NAME="${PACKAGE_DIR##*/}"

    echo "INFO: Storing changelog for \"$PACKAGE_NAME\" package using command \"git log --oneline -- $PACKAGE_DIR\"."
    mv -f "$PACKAGE_DIR/Changelog" "$PACKAGE_DIR/Changelog.orig"
    git log --oneline -- "$PACKAGE_DIR" > "$PACKAGE_DIR/Changelog" || : # Ignore errors

    echo "INFO: Making archive \"$TARGET_DIR/$PACKAGE_NAME.tar.gz\" from \"$SOURCE_DIR/$PACKAGE_DIR\" directory."
    tar czf "$TARGET_DIR/$PACKAGE_NAME.tar.gz" -C "$SOURCE_DIR" "$PACKAGE_NAME/" || {
      echo "ERROR: Cannot create tar.gz archive \"$TARGET_DIR/$PACKAGE_NAME.tar.gz\" from \"$PACKAGE_NAME\" directory in \"$SOURCE_DIR\" directory." >&2
      # Restore original changelog file
      mv -f "$PACKAGE_DIR/Changelog.orig" "$PACKAGE_DIR/Changelog"
      return 1
    }

    # Restore original changelog file
    mv -f "$PACKAGE_DIR/Changelog.orig" "$PACKAGE_DIR/Changelog"
  done

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  make_tar_archives "$@"
}
