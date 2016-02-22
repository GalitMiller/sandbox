#!/bin/bash
set -u

# Show logs of various services which are necessary for CMC to work.
# First argument: log name (see cases below) or "all" for all logs. Default value: "container".
# Second argument: container name. Default value: "bpac".

# Dump content of a log file(s)
dcat() {
  local I
  for I in "$@"
  do
    if [ -s "$I" ] # If log file exists and not empty
    then
      echo -e "\n\n ======== Content of log file $I:"
      cat "$I" || :
    fi
  done
}

# Show journal of a service(s)
jcat() {
  local I
  for I in "$@"
  do
    echo -e "\n\n ======== Log of $I:"
    journalctl --no-pager --all --unit "$I" || :
  done
}

show_log() {
  local LOG_TYPE="${1:-systemd}"

  case "$LOG_TYPE" in
    s|systemd|all)
      echo -e "\n\n ======== systemd messages:"
      journalctl --no-pager --all -x || :
    ;;&

    fb|bpac-first-boot|all)
      jcat bpac-first-boot.service
    ;;&

    b|bpac|all)
      dcat /var/log/bpac/bpac.log /var/log/httpd/bpac*
    ;;&

    B|bricata|all)
      dcat /var/log/bricata/development.log /var/log/bricata/production.log
    ;;&

    W|bricata-workers|all)
      jcat bbpac-bricata-workers.service
      dcat /var/log/bricata/delayed_job.log
    ;;&

    h|httpd|all)
      jcat httpd.service
      dcat /var/log/httpd/ssl_access_log /var/log/httpd/ssl_error_log /var/log/httpd/error_log
    ;;&

    m|mysql|mysqld|mariadb|all)
      jcat mariadb.service
      dcat /var/log/mariadb/mariadb.log
    ;;&

    r|redis|all)
      jcat redis.service
      dcat /var/log/redis/redis.log
    ;;&

    c|celery|all)
      jcat celery.service
      dcat /var/log/celery/celery.service.log
    ;;&

    cb|celerybeat|all)
      jcat celerybeat.service
      dcat /var/log/celery/celerybeat.service.log
    ;;&
  esac
}

main() {
  local I
  for I in "$@"
  do
    show_log "$I"
  done
}

main "$@"
