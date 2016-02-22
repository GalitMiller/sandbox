#!/bin/bash
set -ue

# File: /etc/suricata/bricata.conf
# String: output database: log, mysql, user=root password=bricata dbname=bricata host=cmc

set_mysql_server_parameters_for_suricata() {
  local MYSQL_HOST="${1:?Argument is required: MySQL host name, e.g. \"cmc\".}"
  local MYSQL_USER="${2:?Argument is required: MySQL user name, e.g. \"root\".}"
  local MYSQL_PASSWORD="${3:?Argument is required: MySQL user password, e.g. \"br1c@t@\".}"
  local MYSQL_DATABASE="${4:?Argument is required: MySQL database name, e.g. \"bricata\".}"

  local CONF_FILE="${SURICATA_CONF_FILE:-/etc/suricata/bricata.conf}"
  local TMP_FILE="$CONF_FILE.new"

  # Test for forbidden characters
  case "$MYSQL_HOST$MYSQL_USER$MYSQL_PASSWORD$MYSQL_DATABASE" in
    *' '*|*$'\t'*|*'='*|*','*)
      echo "ERROR: Parameters MUST NOT contain following special characters: space, tab, '=', or ','." >&2
      return 1
    ;;
  esac

  local CONFIGURATION_STRING="output database: log, mysql, user=$MYSQL_USER password=$MYSQL_PASSWORD dbname=$MYSQL_DATABASE host=$MYSQL_HOST"
  echo "INFO: Configuration string for Suricata: \"$CONFIGURATION_STRING\"."

  # First, exclude line with "^output database:" string from configuration file
  grep --invert-match --extended-regexp '^output database:'  "$CONF_FILE" >"$TMP_FILE" || {
    echo "ERROR: Cannot grep configuration file \"$CONF_FILE\" and write output to \"$TMP_FILE\"." >&2
    return 1
  }

  [ -s "$TMP_FILE" ] || {
    echo "ERROR: File \"$CONF_FILE\" is empty. Refusing to continue because it is sign of posible race condition or missconfiguration." >&2
    rm -f "$TMP_FILE"
    return 1
  }

  # Append address of CMC to end of new hosts file
  sh -c "echo \"$CONFIGURATION_STRING\" >>\"$TMP_FILE\""

  # Replace existing configuration file
  mv -f "$TMP_FILE" "$CONF_FILE" || {
    echo "ERROR: Cannot move temporary file \"$TMP_FILE\" over \"$CONF_FILE\"." >&2
    rm -f "$TMP_FILE"
    return 1
  }

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  if [ "${CONFIG_MODE:-}" == "yes" ] ; then
    # Get parameters from environment variables when in CONFIG_MODE
    set_mysql_server_parameters_for_suricata \
      "${MYSQL_HOST:?Variable is required: MYSQL_HOST: MySQL host name, e.g. \"cmc\".}" \
      "${MYSQL_USER:?Variable is required: MYSQL_USER: MySQL user name, e.g. \"root\".}" \
      "${MYSQL_PASSWORD:?Variable is required: MYSQL_PASSWORD: MySQL user password, e.g. \"br1c@t@\".}" \
      "${MYSQL_DATABASE:?Variable is required: MYSQL_DATABASE: MySQL database name, e.g. \"bricata\".}"
  else
    # Get parameters from script arguments
    set_mysql_server_parameters_for_suricata "$@"
  fi
}
