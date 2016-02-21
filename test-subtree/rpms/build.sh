#!/bin/bash
set -ue
BIN_DIR="$(readlink -f "$(dirname "$0" )" )" #"

. "$BIN_DIR/../settings.sh"

# By default, use "mock" for clean build.
# Set RPMS_FAST_BUILD to "yes" to use "rpmbuild" directly, which is
# faster way to build, but packages will be built for host OS instead of
# target OS, and build dependencies will not be tested, because they are
# already installed on host.
FAST_BUILD="${RPMS_FAST_BUILD:-no}"

# Name of target OS configuration to build RPMs for. See mock
# documentation and /etc/mock/ directory, e.g. RPMS_TARGET_OS="epel-7-x86_64"
# Ignored when FAST_BUILD is set to "yes" (because mock is not used at all in this case).
# bpac-backend requires additional modules to execute tests during build,
# so we need custom mock configuration, with BPAC yum repository for external dependencies.
TARGET_OS="${RPMS_TARGET_OS:-$BIN_DIR/mock-config/bpac-epel-7-x86_64.cfg}"


# Import functions from library in ./build-scripts/
DEFINE_ONLY="yes"
for FILE in "$BIN_DIR"/build-scripts/*.sh
do
  source "$FILE"
done

# Build rpm packages, then store them to directory, generate yum repo and
# add this repo to local yum configuration.
# First argument: name of directory to store packages into.
main() {
  local REPO_DIR="${1:-"$BIN_DIR"/../dockerfiles/var/lib/bpac-yum-repo}"

  mkdir -p "$REPO_DIR" || {
    echo "ERROR: Cannot create directory \"$REPO_DIR\" to store built RPM packages and yum repository into." >&2
    return 1
  }
  [ -w "$REPO_DIR" ] || {
    echo "ERROR: Cannot write to directory \"$REPO_DIR\" to store built RPM packages and yum repository into." >&2
    return 1
  }
  REPO_DIR="$(readlink -f "$REPO_DIR")" # Convert relative path into absolute path
  echo "INFO: building packages from \"$BIN_DIR\" source directory to \"$REPO_DIR\" target directory."

  rm -rf "$REPO_DIR" || {
    echo "ERROR: Cannot remove directory \"$REPO_DIR\". Cannot clean directory for repository." >&2
    return 1
  }
  mkdir -p "$REPO_DIR" || {
    echo "ERROR: Cannot create directory \"$REPO_DIR\". Cannot make directory for repository." >&2
    return 1
  }

  # Create temporary directory to store .tar.gz archives to make packages from
  local ARCHIVES_TMP_DIR="$(mktemp -d)"

  # Make packages from directories
  make_tar_archives "$BIN_DIR" "$ARCHIVES_TMP_DIR" || return 1 # TODO: uncomment when packages will be there
  make_tar_archive_of_dir "$BIN_DIR/../bricata" "$ARCHIVES_TMP_DIR" "bpac-bricata" || return 1
  make_rpms "$ARCHIVES_TMP_DIR" "$REPO_DIR" "$TARGET_OS" || return 1
  rm -rf "$ARCHIVES_TMP_DIR"

  return 0
}

main "$@"
