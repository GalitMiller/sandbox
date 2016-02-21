#!/bin/bash
set -ue

# Install local yum repository, so yum will be able to install packages from it..

install_yum_repository() {
  local PACKAGES_DIR="${1:?Argument required: path to directory with RPM packages and yum repodata directory.}"
  local REPO_NAME="${2:?Argument required: name of yum repository, e.g. \"bricata-local\".}"
  local YUM_REPOS_D="${YUM_REPOS_CONF_DIR:-/etc/yum.repos.d/}"

  # Sanity checks
  [ -d "$PACKAGES_DIR" ] || {
    echo "ERROR: Not a directory: \"$PACKAGES_DIR\". Cannot make yum repository here. It must be an existing directory with binary RPM packages." >&2
    return 1
  }
  (( $(ls "$PACKAGES_DIR"/*.rpm | wc -l) > 0 )) || {
    echo "ERROR: No RPM packages in \"$PACKAGES_DIR\". It must be an existing directory with binary RPM packages and yum repository metadata generated." >&2.
    return 1
  }
  [ -d "$PACKAGES_DIR/repodata" ] || {
    echo "ERROR: Not a yum repository in \"$PACKAGES_DIR\" directory, no \"repodata\" subdirectory with yum metadata." >&2
    return 1
  }

  cat <<YUM_REPO_INI >"$YUM_REPOS_D/$REPO_NAME.repo" || { echo "ERROR: Cannot write file to \"$YUM_REPOS_D/$REPO_NAME.repo\" file. You need root permissions to write to system configuration directory." ; return 1 ; }
[$REPO_NAME]
name=$REPO_NAME
failovermethod=priority
baseurl=file://$PACKAGES_DIR/
enabled=1
gpgcheck=0
skip_if_unavailable=False
YUM_REPO_INI

}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {
  install_yum_repository "$@"
}
