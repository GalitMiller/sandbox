#!/bin/bash
set -ue

#
# Script to shtutdown container cleanly instead of "docker kill bpac"
# (which is similar in effect to hardware reset button).
#

# Container name, to use as reference to container, e.g. "bpac" or "staging_bpac".
CONTAINER_NAME="${CONTAINER_NAME:-bpac}"

# Shutdown existing container, so MySQL will be able to save changes to DB.
# Does not work sometimes, bug is reported, see https://bugzilla.redhat.com/show_bug.cgi?id=1201657 .
#docker exec bpac shutdown -h now >/dev/null || :

# Shutdown services individually instead of shutdown of whole container.
docker exec "$CONTAINER_NAME" bpac-container-shutdown.sh >/dev/null 2>&1 || :

# Stop existing container, if any
docker kill "$CONTAINER_NAME" >/dev/null 2>&1 || :
# Remove existing contaienr, if any
docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || :
