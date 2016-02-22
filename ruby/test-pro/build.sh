#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
cd "$BIN_DIR"

# First argument: container tag (e.g. "bpac" or "arnem:5000/release/bpac )
# Rest of arguments: additional options for docker build (e.g. --force-rm=true )

CONTAINER_TAG="bpac"
VERSION_TXT_FILE="dockerfiles/var/www/webapp/target/VERSION.txt"

. "$BIN_DIR/settings.sh"

if (( $# >= 1 ))
then
  CONTAINER_TAG="$1"
  shift # Skip first argument. Rest of arguments are docker options.
fi

# Store information about build host and git version in container
mkdir -p "$(dirname "$VERSION_TXT_FILE")"
(
  echo "BPAC Version ${BPAC_VERSION:-unknown} git:$(git log --oneline -1 2>/dev/null | cut -d ' ' -f 1)"
  echo "Built at: `LANG=en_US date`, jenkins build number: ${BUILD_NUMBER:-none} on host: `hostname`, jenkins build URL: ${BUILD_URL:-none} ."

  echo
  echo "Latest commits:"
  git log -n 10
) > "$VERSION_TXT_FILE" || :

# Build DEB packages
pushd ./debs
./build.sh || {
  echo "WARNING: Build of deb's didn't pass successfully. Check the log file for errors and/or warnings." >&2
}
popd

# Build RPMS packages
pushd ./rpms
./build.sh || {
  echo "ERROR: Build of RPM's didn't pass successfully. Check the log file for errors and/or warnings." >&2
  exit 1
}
popd

# Build docker image and label it as "bpac"
docker build --pull="${PULL:-true}" -t "$CONTAINER_TAG" "$@" .
