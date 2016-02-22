#!/bin/bash
set -ue

#
# Rules update script
# Fetches latest rules from CMC Git repo and reloads suricata and bricata daemons
#

# Flags
FORCE_RESTART_SURICATA_PROCESS="no"

# Runtime variables
ACT_FILE="/etc/sensor-activated-by-cmc"
RULES_FOLDER_ORIGIN="rules"
RULES_FOLDER="rules.bpac"
RULES_DIR_ORIGIN="/etc/suricata/$RULES_FOLDER_ORIGIN"
RULES_DIR="/etc/suricata/$RULES_FOLDER"
RULES_TMP_FILE="/tmp/bpac-rules.tar.gz"
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
SENSOR_MODEL_FILE="/sensor-model"
CUSTOM_RULES_FILENAME="custom.rules"
CUSTOM_RULES_FILE="$RULES_DIR_ORIGIN/$CUSTOM_RULES_FILENAME"
OINK_CMC_MESSAGE="# CMC_SECTION"
OINK_FILE="/etc/oinkmaster.conf"
POLICY_BLOCK_PATTERN="# ACTION block"


#
# Argument-based variables (defaults)
#
BPAC_GIT_SENSOR_BRANCH="master"
BPAC_INTERFACES="br0"
BPAC_POLICY_FILE=" "
BPAC_ACTIONS="alert"
BPAC_DEPLOYMENT_MODE="IDS"

#
# FIXME: Read from parameters and/or postprocess variables
#
SURICATA_BINARY="suricata"
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
SURICATA_LOG_DIR="/var/log/suricata"
SURICATA_OPTS_INTERFACES="-i br0"
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

  local EXP_ARG_COUNT=2

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
    echo "    $0 <SENSOR_BRANCH> <INTERFACE>"
    echo "Example:"
    echo "    $0 \"sensor-001\" \"br0\""
    echo 
    return 1
  fi

  BPAC_GIT_SENSOR_BRANCH="${1:?Argument is required: name of branch for this sensor in GIT repository, e.g. \"sensor1\".}"
  BPAC_INTERFACES="${2:?Argument is required: interfaces list that policy has to be applied to, e.g. \"eth0:eth1\"}"
  #BPAC_POLICY_FILE="${3:?Argument is required: policy file name, e.g. \"policy_new_pol.rules\"}"
  #BPAC_ACTIONS="${4:?Argument is required: action to be performed by the daemon, e.g. \"log:block\"}"
  #BPAC_DEPLOYMENT_MODE="${5:?Argument is required: policy deployment mode, e.g. \"IDS\"}"

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

  # Check if Suricata GIT-based rules directory exists
  if [ ! -d "$RULES_DIR" ];
  then
    echo "ERROR: Unable to find Suricata rules directory $RULES_DIR. Did you perform the sensor activation?" >&2
    return 1
  fi

  # Check if original (typically, /etc/suricata/rules) folder exists
  if [ ! -d "$RULES_DIR_ORIGIN" ];
  then
    echo "ERROR: Unable to find Suricata rules directory $RULES_DIR_ORIGIN. Are you running the script on sensor?" >&2
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
#  Cleaup rules directory. It removes all *.rules files except "custom.rules"
###
function cleanup_rules_dir() {

  local _RULES_DIR="${1:?Argument is required: path to Suricata rules folder, e.g. \"/etc/suricata/rules\".}"

  pushd $_RULES_DIR
  find ! -name "$CUSTOM_RULES_FILENAME" -name "*.rules" -type f -exec rm -f {} + || {
    echo "ERROR: Unable to remove files from directory $_RULES_DIR"
    return 1
  }
  popd

}

###
#  Generate merged rules file
###
function make_custom_rules_file() {

  # Check if file exists
  if [ -f "$CUSTOM_RULES_FILE" ];
  then
    echo "INFO: File $CUSTOM_RULES_FILE already exists. We'll keep a backup copy of it"
    cp -a "$CUSTOM_RULES_FILE" "${CUSTOM_RULES_FILE}.backup" || {
      echo "ERROR: Unable to create a backup copy of the file ${CUSTOM_RULES_FILE}"
      return 1
    }
  fi

  # Clear the file
  echo > "$CUSTOM_RULES_FILE"

  # Merge all file into one
  cat $RULES_DIR/*.rules >> "$CUSTOM_RULES_FILE"

}

###
#  Insert proper file include value in suricata.yaml
###
function update_suricata_yaml() {

  # Let's check if the suricata.yaml is including custom.rules file
  if [ -z "`cat $SURICATA_CONFIG | grep -e "^ - $CUSTOM_RULES_FILENAME"`" ]
  then
    # Let's patch the file to include custom logs
    echo "WARN: No $CUSTOM_RULES_FILENAME file included. Adding it to $SURICATA_CONFIG"
    sed -i "/rule-files:/a \ - $CUSTOM_RULES_FILENAME" $SURICATA_CONFIG || {
      echo "ERROR: Unable to patch file $SURICATA_CONFIG by adding reference to file $CUSTOM_RULES_FILENAME"
      return 1
    }
   
    # Since we've modified suricata.yamlfile so the process(es) have to be restarted
    FORCE_RESTART_SURICATA_PROCESS="yes"
 
  fi

}

###
#  Flush rules to Suricata using OINKmaster tool
###
# Algorithm:
# 1. Re-generate SID MAPs
# 2. Compress "rules" folder to tar.gz file
# 3. Run OINK updater with -u file:///tmp/bpac-rules.tar.gz
# The trick is that we kind of importing the same rules folder
# into the system once again but we pass it through 
# specifically configured OINKmaster tool that will only have those
# rules/file enabled that we need
function flush_rules_with_oinkmaster() {


  local _RULES_DIR="$RULES_DIR_ORIGIN"

  # Cleanup the directory
  cleanup_rules_dir $_RULES_DIR || {
    echo "ERROR: Unable to clean directory $_RULES_DIR"
    return 1
  }

  # Re-generate SID maps
  generate_sid_maps "$_RULES_DIR" || {
    echo "ERROR: Unable to generate sid maps"
    return 1
  }

  # Create an archive of the rules directory
  echo "Archiving rules to file $RULES_TMP_FILE" 
  pushd "/etc/suricata"
  tar cfz $RULES_TMP_FILE ./$RULES_FOLDER_ORIGIN || {
    echo "ERROR: Cannot create archive $RULES_TMP_FILE of folder $_RULES_DIR"
    return 1
  }
  popd
  echo "Done"

  # Import the rules file
  echo "Flushing rules..."
  /usr/sbin/oinkmaster -C "$OINK_FILE" -o "/etc/suricata/$RULES_FOLDER_ORIGIN" -u "file://$RULES_TMP_FILE" -v || {
    echo "ERROR: Unable to reload/flush rules with OINKmaster tool"
    return 1
  }
  echo "Done"

}


###
#  Update OINK file
### 
function update_oink_file() {

  local _SID="0" 
  local _ENABLE_SIDS="enablesid "

  # Check if /etc/oinkmaster.conf has the place holder
  # and remove the old sestion
  if [ ! -f "$OINK_FILE" ]
  then
    echo "ERROR: File $OINK_FILE doesn't exists"
    return 1
  fi 

  # Backup the original file
  if [ ! -f "${OINK_FILE}.origin" ];
  then
    echo "INFO: Saving original ${OINK_FILE} file"
    cp -a "${OINK_FILE}" "${OINK_FILE}.origin" || {
      echo "ERROR: Unable to save file ${OINK_FILE} to ${OINK_FILE}.origin"
      return 1
    }
  fi

  # Check if file has a placeholder in it
  if [ -n "`cat ${OINK_FILE}.working | grep -e "^$OINK_CMC_MESSAGE"`" ];
  then
    # Remove all after the $OINK_CMC_MESSAGE pattern in OINK file
    awk "{print} /$OINK_CMC_MESSAGE/ {exit}" ${OINK_FILE} >  ${OINK_FILE}.working
  else
    cp -a ${OINK_FILE} ${OINK_FILE}.working
  fi

  # Now file is clean and ready to have the custom configuration added
  echo $OINK_CMC_MESSAGE >> ${OINK_FILE}.working
  echo "# Machine generated. Do not edit." >> ${OINK_FILE}.working

  # Defining templates
  echo "define_template make_drop \"^alert\s\" | \"drop \"" >> ${OINK_FILE}.working


  # Block all files
  echo "# Block all files except custom rules" >> ${OINK_FILE}.working
  for _BLOCK_FILE in $RULES_DIR_ORIGIN/*.rules
  do
    _BLOCK_FILE="`filename "$_BLOCK_FILE"`"
    [ "${_BLOCK_FILE}" == "${CUSTOM_RULES_FILENAME}" ] && continue
    echo "skipfile $_BLOCK_FILE" >> ${OINK_FILE}.working
  done
  

  # Enable SIDs
  echo "# Enable SIDs" >> ${OINK_FILE}.working
  # Add enabled signatures 
  while read _RULE; 
  do
    # If the line is commented -- ignore it
    [[ "$_RULE" =~ ^#.*$ ]] && continue
    # Extracting sid from rule string 
    _SID="`echo ${_RULE#*sid:} | cut -d ";" -f 1`"
    if [ -n "$_SID" ];
    then
      echo "$_ENABLE_SIDS $_SID" >> ${OINK_FILE}.working
    else
      echo "WARN: Unable to extract SID value from rule: $_RULE"
      echo "Rule skipped!"
    fi
  done < $CUSTOM_RULES_FILE

  
  #
  # Now, a tricky part: let's make particular rules blocking depending on the policy action
  #

  # Block rules

  echo "# Turn signatures with these sids to block mode" >> ${OINK_FILE}.working

  # Let's iterate through each rule file in rules
  for RULE_FILE in $RULES_DIR/*.rules
  do
   
   if [ -n "`head -1 $RULE_FILE | grep -e "$POLICY_BLOCK_PATTERN"`" ]
   then
   
     echo "INFO: File $RULE_FILE is set for block mode"

     while read _RULE; 
     do
       # If the line is commented -- ignore it
       [[ "$_RULE" =~ ^#.*$ ]] && continue

       # Extracting sid from rule string 
       _SID="`echo ${_RULE#*sid:} | cut -d ";" -f 1`"

       if [ -n "$_SID" ];
       then
         echo "use_template make_drop $_SID" >> ${OINK_FILE}.working
       else
         echo "WARN: Unable to extract SID value from rule: $_RULE"
         echo "Rule skipped!"
       fi

     done < $RULE_FILE

   fi

  done

  # We are done. Let's copy the working file as a new one
  cp -a ${OINK_FILE} ${OINK_FILE}.backup
  cp -a ${OINK_FILE}.working ${OINK_FILE}

}

###
#  Re-generate sid maps
###
function generate_sid_maps() {

  local _RULES_DIR="${1:?Argument is required: path to Suricata rules folder, e.g. \"/etc/suricata/rules\".}"

  ### Re-generate sid-msg.map
  echo "Generating updated SID MSG map..."
  /usr/bin/create-sidmap.pl "$_RULES_DIR" > "$_RULES_DIR/sid-msg.map"
  echo "Generating updated messages map..."
  cat "$_RULES_DIR/sid-msg.map" | awk -F '|' '{print "1 || "$1" || "$3}' > "$_RULES_DIR/gen-msg.map"

}


###
#  Adding .rules file to the YAML configuration file
###
### DEPRECATED and TO BE REMOVED
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
#  Restart Suricata processes
###
function restart_suricata_process() {

  #  cat "/proc/1929/cmdline"|sed 's/\x0/ /g'
  local SPIDs="`ps -ef | grep -v grep | grep 'suricata -c' | awk '{print $2}' | tr '\n' ' '`"
 
  echo "INFO: Found Suricata PIDs: $SPIDs"
 
  for _PID in $SPIDs
  do
    [ ! -f "/proc/$_PID/cmdline" ] && {
      echo "WARN: Cannot get command line for Suricata process with $_PID"
      continue
    }
    _CMDLN="`cat "/proc/$_PID/cmdline"|sed 's/\x0/ /g'`"

    # Reload the process in a subshell
    echo "INFO: Restarting Suricata process with PID $_PID by calling command:"
    echo "	$_CMDLN"
    ( 
      kill "$_PID" 2>&1
      # Wait for process to die
      echo "INFO: Waiting for process $_PID to stop"
      while kill -0 "$_PID"; do
        sleep 1
      done
      echo "INFO: Process $_PID killed"
      # Spawn a new one with the same command line
      echo "INFO: Now starting new process by calling: $_CMDLN"
      `$_CMDLN` 2>&1
      # Wait for ready
      echo "Wating for 3 seconds for Suricata process to become ready..."
      sleep 3
      echo "Done"
    ) || {
      echo "ERROR: Unable to restart Suricata process. PID: $_PID"
      return 1
    }
  done

}


###
#   Restart Suricata and Bricata daemons
###
function restart_daemons_default() {
  ### Restart Suricata IDS
  echo "Stopping existing running IDS processes"
  service bricata stop || {
    echo "WARN: Unable to stop 'bricata' service. Most likely no processes were running."
  }

  #
  # Flush the rules
  #
  flush_rules_with_oinkmaster || {
    echo "ERROR: An error occured when trying to flush rules with OINKmaster tool"
    return 1
  }

  #
  # Reload Suricata
  #
  # If we force the restart of suricata daemon
  if [ "$FORCE_RESTART_SURICATA_PROCESS" == "yes" ];
  then
    echo "WARN: Suricata process is forced to perform a hard restart"
    restart_suricata_process || {
      echo "ERROR: Unable to restart Suricata process"
      return 1
    }
  else
    echo "INFO: No Suricata restart is forced. Doing a standard rules reload with -USR2"
    SPID="`ps -ef | grep -v grep | grep 'suricata -c' | awk '{print $2}' | tr '\n' ' '`"
    if [ -n "$SPID" ];
    then
      # We have Suricata already running on interface $SURICATA_OPTS_INTERFACES
      echo "INFO: We found that Suricata is running. PIDs: $SPID. So, we can do kill -USR2."
      kill -USR2 $SPID 2>&1 || {
        echo "ERROR: Unable to do \"kill -USR2\" on Suricata process with PID $SPID"
      }
    else
      # Suricata is not running at all
      # This is not good and system cannot continue
      echo "ERROR: Suricata is not running at all. This is an exception and we are exiting. Please, use /etc/proaccel-setup.sh program to set the services up."
      return 1
    fi
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
#  This function validates if Suricata IPS/IDS is running
###
function verify_suricata_running() {

  local IS_EXCEPTION="${1:-no}"

  local SPID="`ps -ef | grep -v grep | grep 'suricata -c' | awk '{print $2}' | tr '\n' ' '`"
  if [ -n "$SPID" ];
  then
    # We have Suricata already running
    echo "INFO: We found that Suricata is running. PIDs: $SPID."
  else
    # Suricata is not running at all
    # This is not good and system cannot continue
    echo "ERROR: Suricata IPS/IDS daemon is not running at all. Please, use /etc/proaccel-setup.sh program to set the services up and/or check Suricata log file for more details."
    if [ "$IS_EXCEPTION" == "yes" ];
    then
      echo "CRITICAL: Suricata process is expected to be running but it is not. Exiting now."
      echo "DEBUG: Processes that match \"suricata\" keyword:"
      ps -ef | grep -v grep | grep 'suricata' 2>&1 || {
        echo "ERROR: Unable to get processes matching keyword \"suricata\""
      } 
      return 1
    fi
  fi
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

  make_custom_rules_file || return 1

  update_oink_file || return 1

  update_suricata_yaml || return 1

  model_based_daemon_restart || return 1

  verify_suricata_running "yes" || return 1

}

main $@ || exit 1
