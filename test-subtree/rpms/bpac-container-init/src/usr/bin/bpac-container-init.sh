#!/bin/bash
set -uex

# Script which will be run at startup of container

# Container inherits limit on number of opened files from Docker(1.5), which is very high (1M),
# so return it back to sane 1K limit, otherwise processes in container will use too much memory
# (size of file descriptor * 1M per each process).
ulimit -n 1024

# Systemd cannot use NSPAWN in non-privileged container.
# No longer necessary, because docker(?) will put overrides in /run/systemd/system, but do it anyway.
perl -pi -e 's/PrivateTmp/#PrivateTmp/' /usr/lib/systemd/system/*.service

# Systemd cannot adjust out-of-memory killer in non-privileged container
perl -pi -e 's/OOMScoreAdjust/#OOMScoreAdjust/' /usr/lib/systemd/system/*.service

# Run systemd as PID 1
exec /usr/lib/systemd/systemd
