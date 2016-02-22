#!/bin/sh
set -ue

RULES_URL="http://rules.emergingthreatspro.com/9785079145606566/suricata-1.1.0/etpro.rules.tar.gz"
SURICATA_RULES_DIR="/etc/suricata/rules"

function import_rules() {
  # Print message to file or to stdout, by default.
  local  FILENAME="${1:-/dev/stdout}"

  # Create Suricata rules directory
  mkdir -p $SURICATA_RULES_DIR

  # Run OINKmaster to pull the latest rules
  /usr/bin/oinkmaster -v -C /etc/oinkmaster.conf -u $RULES_URL -o $SURICATA_RULES_DIR >> "$FILENAME" 2>&1 || {
    echo "ERROR: Unable to pull rules from ET repository. See $FILENAME for more details."
    return 1
  }

  # Import rules
  for RULE_FILE in $SURICATA_RULES_DIR/*.rules
  do

    # Import each file one by one
    echo "INFO: Importing file $RULE_FILE into BPAC database"
    nice -n 20 bpac-manage.sh signatures import -p $RULE_FILE -f suricata >> "$FILENAME" 2>&1 || {
      echo "ERROR: There were errors while performing import. Please, see log file $FILENAME for more details"
    }

  done

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  if [ "${CONFIG_MODE:-}" == "yes" ] ; then
    # Get parameters from environment variables when in CONFIG_MODE
    import_rules "${HELLOWORLD_MESSAGE_FILENAME:?Variable is required: LOG_FILENAME: path to file to store log output in.}"
  else
    # Get parameters from script arguments
    import_rules "$@"
  fi
}
