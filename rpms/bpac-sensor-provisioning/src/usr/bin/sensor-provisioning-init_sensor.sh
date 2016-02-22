#!/bin/bash
set -ue
# Execute provisioning scripts on sensor or generate script to be executed on sensor.

# Generate standalone script from configuration files in
# /etc/bricata/sensor-provisioning.d, user supplied options and modules in
# /usr/lib/bricata/sensor/provisioning.d.
#
# Additonal options are passed in SCRIPT_ADDITIONAL_OPTIONS array in form "OPTION=value" (or any other valid bash statement).
make_init_script() {
  local CONF_DIR="${BRICATA_SENSOR_PROVISIONING_CONF_DIR:-/etc/bricata/sensor-provisioning.d}"
  local SCRIPTS_DIR="${BRICATA_SENSOR_PROVISIONING_SCRIPTS_DIR:-/usr/lib/bricata/sensor/provisioning.d}"

  # Sanity checks
  [ -d "$CONF_DIR" ] || {
    echo "ERROR: Cannot read configuration files from \"$CONF_DIR\": directory is not found." >&2
    return 1
  }
  [ -d "$SCRIPTS_DIR" ] || {
    echo "ERROR: Cannot read script files from \"$SCRIPTS_DIR\": directory is not found." >&2
    return 1
  }
  (( $(ls "$CONF_DIR"/*.sh | wc -l ) > 0 )) || {
    echo "WARNING: Directory \"$CONF_DIR\" contains no configuration files with .sh extension." >&2
  }
  (( $(ls "$SCRIPTS_DIR"/*.sh | wc -l ) > 0 )) || {
    echo "ERROR: Directory \"$SCRIPTS_DIR\" contains no script files with .sh extension to run." >&2
    return 1
  }

  echo "#!/bin/bash"
  echo "set -ue"
  echo "CONFIG_MODE='yes'"

  echo "#"
  echo "# Configuration"
  echo "#"
  echo

  cat "$CONF_DIR"/*.sh || {
    echo "WARNING: Cannot read one or more configuration files:" "$CONF_DIR"/*.sh >&2
  }
  echo
  echo "#"
  echo "# Additional options"
  echo "#"
  echo
  for OPTION in "${SCRIPT_ADDITIONAL_OPTIONS[@]:+${SCRIPT_ADDITIONAL_OPTIONS[@]}}"
  do
    echo "$OPTION"
    echo
  done

  echo "#"
  echo "# Scripts"
  echo "#"
  echo
  cat "$SCRIPTS_DIR"/*.sh || {
    echo "ERROR: Cannot read one or more files:" "$SCRIPTS_DIR"/*.sh >&2
    return 1 # Exit from subshell
  }

  echo "#"
  echo "# Disable nightly oinkmaster updates."
  echo "#"
  echo
  echo "cat /var/spool/cron/crontabs/root | grep -v oinkmaster > /tmp/cronjob_oinkmaster_disable && cat /tmp/cronjob_oinkmaster_disable > /var/spool/cron/crontabs/root"

  echo "#"
  echo "# END"
  echo "#"
}

# Execute script using "ssh USER@HOST sudo bash -s" to run local script on remote host without uploading it.
# Requires key-based access via ssh and passwordless sudo (full equivalent of root user).
execute_scripts_on_remote_host() {
  # First three arguments are login, host address, and port number
  local LOGIN="${1:?Argument required: Login name to use, when connecting to remote host, e.g. \"root\".}"
  local HOST="${2:?Argument required: name of host to connect to using ssh.}"
  local SSH_PORT="${3:?Argument required: port of ssh daemon to connect to, e.g. 22.}"

  # Execute scripts
  make_init_script | ssh -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "${SSH_TO_SENSOR_COMMAND_ADDITIONAL_OPTIONS[@]:+${SSH_TO_SENSOR_COMMAND_ADDITIONAL_OPTIONS[@]}}" -p "$SSH_PORT" "$LOGIN@$HOST" 'sudo bash -s'

  # Check exit codes of cat, ssh and bash
  local EXIT_CODES="${PIPESTATUS[*]}"
  (( ${EXIT_CODES// /} == 0 )) || {
    # Posible EXIT_CODES values: "N 0" (cat failed), "0 N" (ssh or bash script failed), "N N" (both)
    # where N is number in range 1..255.
    case "$EXIT_CODES" in
      *' 0')
        echo "ERROR: Unable to read a script to execute on remote host." >&2
        return 1
      ;;
      '0 '*)
        echo "ERROR: SSH connection or one of commands in scripts are failed on remote host. Host: \"$LOGIN@$HOST\"." >&2
        return 1
      ;;
      *)
        echo "ERROR: Unable to read a script to execute on remote host. Also, SSH connection or one of commands in scripts are failed on remote host. Host: \"$LOGIN@$HOST\"." >&2
        return 1
      ;;
    esac
  }
  return 0
}

# Connect to sensor via ssh and execute generated script.
# Firs three arguments are login, host, and ssh port,
# rest of arguments are options for generated script in form "OPTION=value".
init_sensor_via_ssh() {
  local LOGIN="${1:?Argument required: login name to use, when connecting to remote host, e.g. \"root\".}"
  local HOST="${2:?Argument required: name of host to connect to using ssh.}"
  local SSH_PORT="${3:?Argument required: port of ssh daemon to connect to, e.g. 22.}"
  shift 3 # Discard first 3 arguments
  # Rest of arguments are additional options for scripts, e.g. FOO=bar
  local SCRIPT_ADDITIONAL_OPTIONS=( "$@" ) # For make_script

  execute_scripts_on_remote_host "$LOGIN" "$HOST" "$SSH_PORT" || return 1

  return 0
}

# Generate standalone script and store it to file to be used later.
# First argument is path to file (or "-" to print it to stdout),
# rest of arguments are options for generated script in form "OPTION=value".
make_standalone_script_to_init_sensor() {
  local TARGET_FILE="${1:?Argument required: path to file to store script into or '-' to print script to STDOUT.}"
  shift 1 # Discard first argument
  # Rest of arguments are additional options for scripts, e.g. FOO=bar
  local SCRIPT_ADDITIONAL_OPTIONS=( "$@" ) # For make_script

  case "$TARGET_FILE" in
    '-') # To STDOUT
      make_init_script || {
        echo "ERROR: Cannot make standalone script for sensor initialization." >&2
        return 1
      }
    ;;
    *) # To file
      make_init_script >"$TARGET_FILE" || {
        echo "ERROR: Cannot make standalone script for sensor initialization and store it to file \"$TARGET_FILE\"." >&2
        return 1
      }
    ;;
  esac

  return 0
}

# Connect to remote host and execute script directly or generate script to be deployed and executed using an other method.
# Usage:
# init_sensor init LOGIN HOST SSH_PORT [OPTION=VALUE]...
# init_sensor generate FILE|_ [OPTION=VALUE]...
init_sensor() {
  local MODE="${1:?Argument required: either \"init\", to setup sensor by ssh, or \"generate\", to generate script, which will be retrieved by sensor via web and executed directly.}"
  shift 1 # Discard first argument

  case "$MODE" in
    init)
      init_sensor_via_ssh "$@" || return 1
    ;;
    generate)
      make_standalone_script_to_init_sensor "$@" || return 1
    ;;
    *)
      echo "ERROR: First argument is wrong: either \"init\", to setup sensor by ssh, or \"generate\", to generate script, which will be retrieved by sensor via web and executed directly." >&2
    return 1
  esac
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {
  init_sensor "$@"
}
