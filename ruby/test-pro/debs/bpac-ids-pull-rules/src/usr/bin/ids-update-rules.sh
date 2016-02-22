#!/bin/bash
set -ue

#
# Rules update script
# Fetches latest rules from CMC Git repo and reloads suricata and bricata daemons
#

ACT_FILE="/etc/sensor-activated-by-cmc"
RULES_FOLDER="rules.bpac"
RULES_DIR="/etc/suricata/$RULES_FOLDER"
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
SENSOR_MODEL_FILE="/sensor-model"

#
# Argument-based variables (defaults)
#
BPAC_GIT_SENSOR_BRANCH="master"
BPAC_INTERFACES="eth0"
BPAC_POLICY_FILE=" "
BPAC_ACTIONS="log"
BPAC_DEPLOYMENT_MODE="IDS"

#
# FIXME: Read from parameters and/or postprocess variables
#
SURICATA_BINARY="suricata"
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
SURICATA_LOG_DIR="/var/log/suricata"
SURICATA_OPTS_INTERFACES="-i eth0 -i lo"
SURICATA_POLICY_OPTS_RULE_FILES=" "
SURICATA_PID="/var/run/suricata.pid"

# $BRICATA_BINARY -q -c $BRICATA_CONFIG -d $SURICATA_LOG_DIR -f unified2.alert -w $BRICATA_WALDO -D &
BRICATA_BINARY="/usr/local/bin/bricata"
BRICATA_CONFIG="/etc/suricata/bricata.conf"
BRICATA_WALDO="/var/log/suricata/suricata.waldo"

###
#  Prepare parameters
#  Call example:
#     prepare_params $@
###
function prepare_params() {

  local EXP_ARG_COUNT=5

  # Load settings from file(s)
  local CONF_DIR="${BRICATA_SETTINGS_DIR:-/etc/bricata/settings.d}"
  
  echo "Reading configuration..."
  for C_FILE in "$CONF_DIR"/*.sh; 
  do 
    source $C_FILE || {
      echo "WARNING: Cannot read one or more configuration files: $C_FILE"  >&2
    }
  done

  # Reload variables afer reading configuration
  RULES_DIR="/etc/suricata/$SURICATA_RULES_FOLDER"

  # Check parameters
  if [ $# -eq 0  ]
  then
    echo "The script requires $EXP_ARG_COUNT arguments which is the name of the branch where sensor's rules are stored"
    echo "Usage:"
    echo "    $0 <SENSOR_BRANCH> <INTERFACES> <POLICY_FILE> <ACTIONS> <DEPLOYMENT_MODE>"
    echo "Example:"
    echo "    $0 \"sensor-001\" \"eth0:eth1\" \"policy_New_Policy_20150601_233315.rules\" \"log\" \"IDS\""
    echo 
    return 1
  fi

  BPAC_GIT_SENSOR_BRANCH="${1:?Argument is required: name of branch for this sensor in GIT repository, e.g. \"sensor1\".}"
  BPAC_INTERFACES="${2:?Argument is required: interfaces list that policy has to be applied to, e.g. \"eth0:eth1\"}"
  BPAC_POLICY_FILE="${3:?Argument is required: policy file name, e.g. \"policy_new_pol.rules\"}"
  BPAC_ACTIONS="${4:?Argument is required: action to be performed by the daemon, e.g. \"log:block\"}"
  BPAC_DEPLOYMENT_MODE="${5:?Argument is required: policy deployment mode, e.g. \"IDS\"}"

  # Prepare interfaces
  SURICATA_OPTS_INTERFACES=""
  IFS=':' read -ra INTERFACES <<< "$BPAC_INTERFACES"
  for INTF in "${INTERFACES[@]}"; do
    SURICATA_OPTS_INTERFACES="$SURICATA_OPTS_INTERFACES -i $INTF"
  done 
  # Trim Interfaces string
  SURICATA_OPTS_INTERFACES="`echo "$SURICATA_OPTS_INTERFACES" | awk '{gsub(/^ +| +$/,"")} {print $0}'`"

  # Interfaces
  SURICATA_POLICY_OPTS_RULE_FILES="-s $RULES_DIR/$BPAC_POLICY_FILE"

}

###
#  Prepare the environment, check sensor readiness etc
###
function prepare() {
  # Check for root
  echo "Checking for root privileges"
  if [ "$(id -u)" != "0" ]; then
     echo "This script must be run as root" 1>&2
     return 1
  fi

  # Check if Suricata rules directory exists
  if [ ! -d "$RULES_DIR" ];
  then
    echo "ERROR: Unable to find Suricata rules directory $RULES_DIR. Are you on running the script in IDS?" >&2
    return 1
  fi

  # Check if sensor is activated
  if [ ! -f "$ACT_FILE" ];
  then
    echo "ERROR: Sensor is not under control of CMC. No reason to continue." >&2
    return 1
  fi

  # Setup GIT to access self-signed certificate
  sudo git config --global http.sslVerify false || {
    echo "ERROR: Unable to set global settings for GIT client" >&2
    return 1
  }

}

###
#  Pulls rule-set from GIT
###
function pull_rules() {

  local BRANCH="${1:-$BPAC_GIT_SENSOR_BRANCH}"
  local DIR="${2:-$RULES_DIR}"

  # Pull the latest rules
  echo "Pulling rules..."
  cd "$DIR"

  sudo git pull || {
    echo "ERROR: Unable to pull the latest rules from remote repository"  >&2
    return 1
  }

  sudo git checkout $BRANCH || {
    echo "ERROR: Cannot switch git repository at \"$DIR\" directory to branch \"$BRANCH\"." >&2
    return 1
  }

}

###
#  Adding .rules file to the YAML configuration file
###

function add_rule_2_file() {

  CUSTOM_CONF_RULES_FILE="policy_rules.yaml"

  # Check if custom rules file exists
  if [ ! -f "/etc/suricata/$CUSTOM_CONF_RULES_FILE" ];
  then
    echo "WARN: No $CUSTOM_CONF_RULES_FILE found. Creating a new one."
    echo "%YAML 1.1" > "/etc/suricata/$CUSTOM_CONF_RULES_FILE"
    echo "---" >> "/etc/suricata/$CUSTOM_CONF_RULES_FILE"
    echo "" >> "/etc/suricata/$CUSTOM_CONF_RULES_FILE"
    echo "rule-files:" >> "/etc/suricata/$CUSTOM_CONF_RULES_FILE"
  fi
 
  # Append the line to the custom rules file
  if [ -z "`cat "/etc/suricata/$CUSTOM_CONF_RULES_FILE" | grep -e "$BPAC_POLICY_FILE"`" ];
  then
    echo "Appending policy file to the custom configuration"
    echo " - $RULES_DIR/$BPAC_POLICY_FILE" >> "/etc/suricata/$CUSTOM_CONF_RULES_FILE"
  else
    echo "Hm... Link to file $RULES_DIR/$BPAC_POLICY_FILE is already in /etc/suricata/$CUSTOM_CONF_RULES_FILE. Skipped to avoid duplicates."
  fi

  # Now, let's check if the file was included into the Suricata's main config
  if [ -z "`cat "$SURICATA_CONFIG" | grep "$CUSTOM_CONF_RULES_FILE"`" ];
  then
    echo "WARN: Custom policy config file $CUSTOM_CONF_RULES_FILE is not included into $SURICATA_CONFIG. Adding it now."
    echo "include: $CUSTOM_CONF_RULES_FILE" >> "$SURICATA_CONFIG"
  fi

  # Let's patch bricata.conf file to correct the path to rules directory
  # First do backup if the file is not patched yet
  [ -z "`cat $BRICATA_CONFIG | grep "\/$RULES_FOLDER\/"`" ] && cp -a "$BRICATA_CONFIG" "${BRICATA_CONFIG}.orig"
  # Apply the patch. The patch is safe to run over the patched file since it will find no pattern to match
  perl -pi -e "s/\/etc\/suricata\/rules\//\/etc\/suricata\/$RULES_FOLDER\//gi" $BRICATA_CONFIG
}

###
#   Restart Suricata and Bricata deamons
###
function restart_daemons_default() {
  ### Restart Suricata IDS
  echo "Stopping existing running IDS processes"
  service bricata stop || {
    echo "WARN: Unable to stop 'bricata' service. Most likely no processes were running."
  }


  ### Re-generate sid-msg.map
  echo "Generating updated SID MSG map..."
  /usr/bin/create-sidmap.pl "$RULES_DIR" > "$RULES_DIR/sid-msg.map"
  echo "Generating updated messages map..."
  cat "$RULES_DIR/sid-msg.map" | awk -F '|' '{print "1 || "$1" || "$3}' > "$RULES_DIR/gen-msg.map"


  #
  # Reload Suricata
  #
  # First, check if the process bound to the same interfaces as we want, is already running
  SPID="`ps -ef | grep -v grep | grep 'suricata -c' | grep -e "$SURICATA_OPTS_INTERFACES" | awk '{print $2}' | tr '\n' ' '`"
  if [ -n "$SPID" ];
  then
    # We have Suricata already running on interface $SURICATA_OPTS_INTERFACES
    echo "INFO: We found that Suricata is running bound to the same interface. So, we can do kill -USR2."
    kill -USR2 $SPID || {
      echo "ERROR: Unable to do \"kill -USR2\" on Suricata process with PID $SPID"
    }
  else
    # Suricata is running on the other interface so we do not have to kill it even.
    # We will just spawn a new process
    echo "INFO: Suricata is running bound to different interface or is not running at all. A new process will be spawn."
    
    echo "----------------------------------------------------------"
    echo "               Starting Suricata Instances                "
    echo "----------------------------------------------------------"

    $SURICATA_BINARY -c $SURICATA_CONFIG -l $SURICATA_LOG_DIR $SURICATA_OPTS_INTERFACES $SURICATA_POLICY_OPTS_RULE_FILES -D && {
      echo "INFO: Successfully started Suricata IDS daemon with options \"$SURICATA_OPTS_INTERFACES $SURICATA_POLICY_OPTS_RULE_FILES\""
    } || {
      echo "ERROR: Unable to start Suricata IDS daemon with options \"$SURICATA_OPTS_INTERFACES $SURICATA_POLICY_OPTS_RULE_FILES\". Check directory $SURICATA_LOG_DIR for more details."
      echo "CRITICAL: IDS might not be operational because of the errors above!"
      return 1
    }

  fi

  echo "----------------------------------------------------------"
  echo "                  Starting Event Logger                   "
  echo "----------------------------------------------------------"

  service bricata start && {
    echo "INFO: Successfully started Bricata Logger"
  } || {
    echo "ERROR: Unable to start Bricata Logger. Check directory $SURICATA_LOG_DIR for more details."
    echo "CRITICAL: Event Logging to CMC might not be operational because of the errors above!"
    exit 1
  }  
}


function restart_daemons_DX500() {

  echo "Not implemented"

}


###
#  Calls propper function to restart the daemons depending on sensor model
###
function model_based_daemon_restart() {
 
 local _SMODEL="default" 

 # Reading sensor model
 # First let's check if file with model information exists
  if [ -f "$SENSOR_MODEL_FILE" ];
  then
    # If it exists then let's check if it has one list only
    if [ `cat $SENSOR_MODEL_FILE | wc -l` -ge 2 ];
    then
      # multiple lines means the file is wrong
      echo "WARN: File $SENSOR_MODEL_FILE doesn't seem to be a valid model file. Proceeding with $_SMODEL model"
    else
      # if there's once line then let's read it into the variable
      _SMODEL="`cat $SENSOR_MODEL_FILE`"
    fi
  else
    # If no file exists then we assume that the model is default
    echo "WARN: Sensor model file ($SENSOR_MODEL_FILE) doesn't exists. Assuming sensor model is $_SMODEL"
  fi

  # Let's make a call to propper function
  case "$_SMODEL" in
    default)
      restart_daemons_default || return 1
      ;;
    DX-500)
      # Place other calls here
      echo "Not implemented"
      restart_daemons_default || return 1
      ;;
    *)
      restart_daemons_default || return 1
  
  esac


}




#
# Main routine
#
function main() {
 
  prepare_params $@ || return 1

  prepare  || return 1

  pull_rules "$BPAC_GIT_SENSOR_BRANCH" "$RULES_DIR" || return 1

  add_rule_2_file || return 1 

  model_based_daemon_restart || return 1

}

main $@ || exit 1
