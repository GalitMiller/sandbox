#!/bin/bash
set -ue

# Script to run BPAC container.
#
# Scripts accepts arguments:
# - first agrument: tag of container
# - rest of arguments: options for docker, e.g. "-d"
#
# Additional environment variables:
# PERSISTENT_MYSQL_DIR - set to "yes" to make MySQL volume persistent by
# mounting host /var/lib/mysql to container /var/lib/mysql.

# Name of container to run, e.g. "bpac" or "192.168.240.83:5000/jenkins/bpac"
CONTAINER_TAG="${1:-bpac}"
shift 1 || : # Skip first argument. Rest of arguments are options for docker run command.

# Container name, to use as reference to container, e.g. "bpac" or "staging_bpac".
CONTAINER_NAME="${CONTAINER_NAME:-bpac}"

# Get name of host and then resolve it to IP address. Usually, it is the primary address of host.
CMC_IP="$(LANG=C host $(hostname) | awk '/has address/ { print $4 }')"

# TODO: detect host time zone, e.g $(basename -a $(dirname $(readlink /etc/localtime)) $(readlink /etc/localtime) | tr '\n' '/' | sed 's/\/$//')
CMC_TZ="UTC"

# Shutdown existing container, so MySQL will be able to save changes to DB.
# Does not work sometimes, bug is reported, see https://bugzilla.redhat.com/show_bug.cgi?id=1201657 .
#docker exec bpac shutdown -h now >/dev/null || :

# Shutdown services individually instead of shutdown of whole container.
docker exec "$CONTAINER_NAME" bpac-container-shutdown.sh >/dev/null 2>&1 || :

# Stop existing container, if any
docker kill "$CONTAINER_NAME" >/dev/null 2>&1 || :
# Remove existing contaienr, if any
docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || :

# Start new container
docker run -d \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /var/lib/mysql:/var/lib/mysql \
  -v /var/www/git:/var/www/git \
  -p 80:5080 \
  -p 443:5443 \
  -p 5080:5080 \
  -p 3306:3306 \
  --name "$CONTAINER_NAME" \
  -e CMC_IP="$CMC_IP" \
  -e CMC_TZ="$CMC_TZ" \
  "${@:+$@}" \
  "$CONTAINER_TAG"


wait_for_service() {
  local EXIT_CODE=0
  local TIME_TO_WAIT=120

  # For all services given to function
  local SERVICE
  for SERVICE in "$@"
  do
    if docker exec "$CONTAINER_NAME" systemctl is-failed -q "$SERVICE"
    then
      echo "ERROR: Service \"$SERVICE\" is failed to start." >&2
      EXIT_CODE=1
      continue
    fi

    # Wait in cycle until systemctl report that service is active
    echo -n "Waiting for \"$SERVICE\" service to start.."
    local I
    for (( I=0; $(docker exec "$CONTAINER_NAME" systemctl is-active -q "$SERVICE" >/dev/null 2>&1; echo $?; )!=0 && I<$TIME_TO_WAIT ; I++ ))
    do
      echo -n "."
      sleep 1
    done

    if (( I==$TIME_TO_WAIT )) ; then
      # Timeout
      echo
      echo "ERROR: Service \"$SERVICE\" is failed to start (timeout)." >&2
      EXIT_CODE=1
    else
      echo " OK"
    fi
  done
  return $EXIT_CODE
}

wait_for_service mariadb.service httpd.service bpac-bricata-workers.service || {
  # Show logs from container
  docker logs "$CONTAINER_NAME"
  docker exec "$CONTAINER_NAME" journalctl -x
}

docker exec "$CONTAINER_NAME" bpac-self-check.sh
