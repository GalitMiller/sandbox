#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
cd "$BIN_DIR"

./build.sh
./d_run-and-test.sh
