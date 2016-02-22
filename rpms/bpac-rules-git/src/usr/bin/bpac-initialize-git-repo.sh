#!/bin/bash
set -ue

GIT_REPO_DIR="${GIT_REPO_DIR:-/var/www/git/rules.git}"

main() {
  # Convert relative path to absolute, if necessary
  local GIT_REPO_DIR="$(readlink -f "$GIT_REPO_DIR")"

  [ ! -e "$GIT_REPO_DIR"/description ] || {
    echo "INFO: Git repository is already exists. Cannot initialize it again. Skipping."
    return 0
  }

  mkdir -p "$GIT_REPO_DIR" || {
    echo "ERROR: Cannot create directory /var/www/git/rules.git."
    return 1
  }

  cd "$GIT_REPO_DIR"

  git --bare init
  echo "exec git update-server-info" > hooks/post-update # Enable hook "git update-server-info"
  chmod a+x hooks/post-update

  # Commit empty README.md into root of repository to initialize it.
  local TMP_WORKING_DIR="$(mktemp -d)"
  mkdir -p "$TMP_WORKING_DIR"
  cd "$TMP_WORKING_DIR"/
  git clone "$GIT_REPO_DIR" rules
  cd rules
  touch README.md
  git add README.md
  git commit -m "Initial commit."
  git push

  return 0
}

main "$@"
