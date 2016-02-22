#!/bin/bash

# Setup python virtual environment for purpose of application development

set -ue

BIN_FILE=`readlink -f "$0"`
BIN_DIR=`dirname "$BIN_FILE"`

cd $BIN_DIR

which virtualenv >/dev/null || {
  echo "ERROR: virtualenv command is not found. Install \"python-virtualenv\" package." >&2
  exit 1
}

# Create virtualenv package
virtualenv flask || {
  echo "ERROR: cannot create python virtual environment using \"virtualenv flask\" command." >&2
  exit 1
}

flask/bin/pip install -U -r ./requirements/all.txt || {
  echo "ERROR: cannot install required modules using command \"flask/bin/pip -r ./requirements/all.txt\"." >&2
  exit 1
}

flask/bin/pip install -U -r ./requirements/tests.txt || {
  echo "ERROR: cannot install required modules using command \"flask/bin/pip -r ./requirements/all.txt\"." >&2
  exit 1
}
