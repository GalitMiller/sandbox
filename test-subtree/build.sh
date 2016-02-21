#!/bin/bash
set -ue
BIN_DIR="$(dirname "$0")"
cd "$BIN_DIR"

# Build RPM packages
( cd rpms ; ./build.sh )

# Build container locally, so it will available for BPAC.
# If you really need, you can push it to arnem to affect builds of others.
docker build -t 192.168.240.82:5000/bricata .
