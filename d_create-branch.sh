#!/bin/bash
set -ue

BRANCH_NAME="${1:?Argument is required: branch name, e.g. \"vlisivka-927\".}"
MASTER_BRANCH="development"

# Always use --rebase with pull.
git config branch.autosetuprebase always
# Pull from upstream branch but push into our own branch, and create it automatically at first push.
git config push.default current


# Create new local branch
git checkout -b "$BRANCH_NAME"

# Track master branch at upstream
git branch -u "origin/$MASTER_BRANCH"

# Show information about branches
git branch -vvv
