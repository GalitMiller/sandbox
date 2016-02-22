#!/bin/bash
set -ue

# Build source (by default) and binary (by request) RPM packages out of
# .tar.gz archives with .spec files inside using "tar-build" method.
make_rpms() {
  local SOURCE_DIR="${1:?Argument required: path to source directory with .tar.gz archives.}"
  local TARGET_DIR="${2:?Argument required: path to target directory to store buit source or binary RPM packages into, e.g. \"/tmp/rpm-packages\".}"
  local MOCK_CONFIG="${3:-epel-7-x86_64}" # Default target distribution: EPEL (CentOS/RedHat/SCL) 7

  # Check is required tools are installed
  [ -n "$(which rpmbuild)" ] || {
    echo "ERROR: This script requires mock tool to build RPM packages in isolation. Install it uisng command \"sudo yum -y install rpm-build\"." >&2
    return 1
  }
  [ "${FAST_BUILD:-no}" == "yes" -o -n "$(which mock)" ] || {
    echo "ERROR: This script requires mock tool to build RPM packages in isolation. Install it using command \"sudo yum -y install mock\", then add this user to mock group using command \"sudo /usr/sbin/usermod -a -G mock $USER\", then relogin user or execute \"sudo su - $USER\"." >&2
    return 1
  }

  # Check is this user belongs to "mock" group, so it will be able to call "mock" command without sudo, using regular expression.
  [[ "${FAST_BUILD:-no}" == "yes" || "$(groups)" =~ (^|[[:space:]])"mock"($|[[:space:]]) ]] || {
    echo "ERROR: This script requires mock group. Add this user to mock group using command \"sudo /usr/sbin/usermod -a -G mock $USER\", then relogin user or execute \"sudo su - $USER\"." >&2
    # NOTE: it is possible to build packages using rpmbuild instead, but they will be built for host OS (Fedora 21 in my case) instead of CentOS 7.1.
    return 1
  }

  # Create directory to put built packages in, in case if it is not already created.
  mkdir -p "$TARGET_DIR" || {
    echo "ERROR: Cannot create directory: $TARGET_DIR. Script will unable to store built packages into that directory." >&2
    return 1
  }

  local RPMBUILD_TMP_DIR="$(mktemp -d)"
  mkdir -p "$RPMBUILD_TMP_DIR" || {
    echo "ERROR: Cannot create temporary directory \"$RPMBUILD_TMP_DIR\"." >&2
    return 1
  }

  # For each .tar.gz file, make RPM package.
  local TGZ_FILE
  for TGZ_FILE in "$SOURCE_DIR"/*.tar.gz
  do
    # Sanity checks
    [ -e "$TGZ_FILE" ] || {
      echo "ERROR: No .tar.gz files are found in \"$SOURCE_DIR\" directory to make RPM packages from." >&2
      return 1
    }
    [ -s "$TGZ_FILE" ] || {
      echo "ERROR: Empty .tar.gz file \"$TGZ_FILE\". RPM will not build RPM package out of it." >&2.
      return 1
    }

    local ARCHIVE_FILE_NAME="${TGZ_FILE##*/}"
    local PACKAGE_NAME="${ARCHIVE_FILE_NAME%.tar.gz}"

    # Extract Changelog file to count line in that file and use that count as minor version of package.
    # Default value (no or emty Changelog file) will be "0".
    local GITVER="$(tar --to-stdout -xzf "$TGZ_FILE" '*/Changelog' 2>/dev/null | wc -l)"

    if [ "${FAST_BUILD:-no}" == "yes" ]
    then
      echo "INFO: Making binary RPM package \"$TARGET_DIR/$PACKAGE_NAME.rpm\" from \"$TGZ_FILE\" archive."
      rm -rf "$RPMBUILD_TMP_DIR"/*
      local OUTPUT
      OUTPUT="$(rpmbuild -tb "$TGZ_FILE" --define "bpacver $BPAC_VERSION" --define "_topdir $RPMBUILD_TMP_DIR" --define "gitver .$GITVER" 2>&1)" || {
        echo "ERROR: Cannot build binary RPM package \"$PACKAGE_NAME\" from \"$TGZ_FILE\" archive in \"$RPMBUILD_TMP_DIR\" directory using command \"rpmbuild -ts '$TGZ_FILE' --define 'bpacver $BPAC_VERSION' --define '_topdir $RPMBUILD_TMP_DIR' --define 'gitver .$GITVER'\"." >&2
        echo "Output of rpmbuild command:" >&2
        echo "$OUTPUT" >&2
        echo
        return 1
        }

      # Find built .rpm file
      local RPM_FILES=( "$RPMBUILD_TMP_DIR"/RPMS/*/*.rpm )
      (( ${#RPM_FILES[@]} > 0 )) || {
        echo "ERROR: No binary RPM packages are found when at least one binary RPM package is expected to be built for \"$TGZ_FILE\" archive: ${RPM_FILES[*]}" >&2
        echo "Output of rpmbuild command:" >&2
        echo "$OUTPUT" >&2
        echo
        return 1
      }
      local RPM_FILE="${RPM_FILES[0]}"
      [ -e "$RPM_FILE" ] || {
        echo "ERROR: No .rpm packages are built from \"$TGZ_FILE\" archive:" >&2
        ls -R "$RPMBUILD_TMP_DIR"/RPMS/*/* >&2 || :
        echo
        return 1
      }
      mv -f "${RPM_FILES[@]}" "$TARGET_DIR" || {
        echo "ERROR: Cannot move files to \"$TARGET_DIR\" using command: \"mv -f ${RPM_FILES[@]} $TARGET_DIR\"." >&2
        return 1
      }
    else
      echo "INFO: Making source RPM package \"$TARGET_DIR/$PACKAGE_NAME.src.rpm\" from \"$TGZ_FILE\" archive."
      rm -rf "$RPMBUILD_TMP_DIR"/*
      local OUTPUT
      OUTPUT="$(rpmbuild -ts "$TGZ_FILE" --define "bpacver $BPAC_VERSION" --define "_topdir $RPMBUILD_TMP_DIR" --define "gitver .$GITVER" 2>&1)" || {
        echo "ERROR: Cannot build source SRPM package \"$PACKAGE_NAME\" from \"$TGZ_FILE\" archive in \"$RPMBUILD_TMP_DIR\" directory using command \"rpmbuild -ts '$TGZ_FILE' --define 'bpacver $BPAC_VERSION' --define '_topdir $RPMBUILD_TMP_DIR' --define 'gitver .$GITVER'\"." >&2
        echo "Output of rpmbuild command:" >&2
        echo "$OUTPUT" >&2
        echo
        return 1
        }

      # Find built .src.rpm file
      local SRPM_FILES=( "$RPMBUILD_TMP_DIR"/SRPMS/*.src.rpm )
      (( ${#SRPM_FILES[@]} == 1 )) || {
        echo "ERROR: Multiple source RPM packages are found when only one source RPM package is expected to be built for \"$TGZ_FILE\" archive: ${SRPM_FILES[*]}" >&2
        echo "Output of rpmbuild command:" >&2
        echo "$OUTPUT" >&2
        echo
        return 1
      }
      local SRPM_FILE="${SRPM_FILES[0]}"
      [ -e "$SRPM_FILE" ] || {
        echo "ERROR: No .src.rpm packages are built from \"$TGZ_FILE\" archive:" >&2
        ls -R "$RPMBUILD_TMP_DIR"/SRPMS >&2
        echo
        return 1
      }

      echo "INFO: Making binary and source RPM packages \"$TARGET_DIR/$PACKAGE_NAME.rpm\" from \"$SRPM_FILE\" source package in clean environment using mock (requires user to be in \"mock\" group)."
      OUTPUT="$(/usr/bin/mock --root="$MOCK_CONFIG" --resultdir="$TARGET_DIR" --define "bpacver $BPAC_VERSION" --define="gitver .$GITVER" --rebuild "$SRPM_FILE" 2>&1)" || {
        echo "ERROR: Cannot build binary and source RPM packages \"$PACKAGE_NAME\" from \"$SRPM_FILE\" source package in clean environment using command \"/usr/bin/mock --root='$MOCK_CONFIG' --resultdir='$TARGET_DIR' --define 'bpacver $BPAC_VERSION' --define='gitver .$GITVER' --rebuild '$SRPM_FILE'\"." >&2
        echo "Output of mock command:" >&2
        echo "$OUTPUT" >&2
        echo
        return 1
      }

      # Sanity check
      echo "INFO: Built packages:"
      ls "$TARGET_DIR/$PACKAGE_NAME"*.rpm || {
        echo "ERROR: no packages for \"$PACKAGE_NAME\" are built." >&2
        echo "Output of mock command:" >&2
        echo "$OUTPUT" >&2
        echo
        return 1
      }
    fi

  done

  # Cleanup
  rm -rf "$RPMBUILD_TMP_DIR"

  echo "INFO: List of built packages:"
  ls "$TARGET_DIR"

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {
  make_rpms "$@"
}
