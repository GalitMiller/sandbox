#!/bin/bash
BIN_DIR="$(dirname "$(readlink -f "$0")")" #"
cat "$BIN_DIR"/all.txt | grep -Ev '#|^$|^-' \
  | tr '[A-Z]' '[a-z]' \
  | sed 's/==/-/; s/^/python-/;' \
  | sed 's/^python-pytest-/pytest-/; s/^python-gitpython-/GitPython-/; s/^python-mysql-python-/MySQL-python-/; s/^python-bpython-/bpython-/; s/python-pylint-/pylint-/; ' \
  | xargs echo sudo yum install -y python-flask-restless-0.17.1dev

# python-invoke-0.9.0
