#!/bin/bash
set -uex
BIN_DIR="$(dirname "$0")"
cd "$BIN_DIR"

test_rebase_push() {
  # Pull latest changes and rebase our commits on top of branch
  git pull --no-edit --rebase

  # Build container
  ./build.sh

  # First, run with clean /var/lib/mysql and /var/www/git directories (setup)
  ./d_clean-persistent-mysql-and-git.sh
  ./d_run-and-test.sh

  # Second, run with populated /var/lib/mysql and /var/www/git directories (upgrade)
  ./d_run-and-test.sh

  # Pull latest changes and rebase our commits on top of branch again
  git pull --no-edit --rebase

  # Push our changes
  git push
}

test_rebase_push "$@"
