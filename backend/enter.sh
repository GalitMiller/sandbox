#!/bin/bash -i

# Enter virtual environment (modify PATH variable, so python from
# flask/bin will be first in the PATH).


BIN_FILE=`readlink -f "$0"`
BIN_DIR=`dirname "$BIN_FILE"`

. "$BIN_DIR"/flask/bin/activate

exec bash -i "$@"
