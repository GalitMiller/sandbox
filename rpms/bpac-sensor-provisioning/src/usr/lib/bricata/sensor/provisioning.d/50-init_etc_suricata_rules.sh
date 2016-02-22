#!/bin/bash
set -ue

# Clone git repository from https://cmc/git/rules.git to /etc/suricata/rules and switch to sensor branch

init_etc_suricata_rules() {
  local GIT_REPO="${1:?Argument is required: URL to GIT repository, e.g. \"https://cmc/git/rules.git\".}"
  local GIT_SENSOR_BRANCH="${2:?Argument is required: name of branch for this sensor in GIT repository, e.g. \"sensor1\".}"
  local TARGET_DIR="${SURICATA_CONF_DIR:-/etc/suricata/}"
  local RULES_DIR="${SURICATA_RULES_DIR:-rules}"

  local CURRENT_CMC_IP=$(grep -e "cmc" "/etc/hosts"|awk '{print $1}')
  if [ -z "$CURRENT_CMC_IP" ] ; then
    echo "ERROR: Remote CMC IP not currently set. Please, make sure that you've configured the sensor via /etc/proaccel-setup.sh script"
    return 1
  fi

  GIT_REPO="https://$CURRENT_CMC_IP/git/rules.git"

  git config --global http.sslVerify false || {
    echo "ERROR: Unable to set global settings for GIT client"
    return 1 
  }

  cd "$TARGET_DIR" || {
    echo "ERROR: Cannot change directory to \"$TARGET_DIR\". Its looks like suricata is not installed here." 2>&1
    return 1
  }

  rm -rf $RULES_DIR || {
    echo "ERROR: Cannot remove directory \"$TARGET_DIR/rules\"." >&2
    return 1
  }

  git clone "$GIT_REPO" $RULES_DIR || {
    echo "ERROR: Cannot clone git repository \"$GIT_REPO\" to \"$TARGET_DIR/rules\"." >&2
    return 1
  }

  cd "$TARGET_DIR/$RULES_DIR" || {
    echo "ERROR: Cannot change directory to \"$TARGET_DIR/$RULES_DIR\", which should contain git repository cloned from \"$GIT_REPO\"." >&2
    return 1
  }

  git checkout "$GIT_SENSOR_BRANCH" || {
    echo "WARNING: Cannot switch git repository cloned from \"$GIT_REPO\" at \"$TARGET_DIR/$RULES_DIR\" directory to branch \"$GIT_SENSOR_BRANCH\". This might be caused by the fact that the propper branch is not created yet or this is first ever time you fetch the repository. Anyway, check out process will take place once again when apply policy process will be initiated." >&2
  }

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  if [ "${CONFIG_MODE:-}" == "yes" ] ; then
    # Get parameters from environment variables when in CONFIG_MODE
    init_etc_suricata_rules \
      "${GIT_REPO_URL:?Variable is required: GIT_REPO_URL: URL to GIT repository, e.g. \"https://cmc/git/rules.git\".}" \
      "${GIT_SENSOR_BRANCH:?Variable is required: GIT_SENSOR_BRANCH: name of branch for this sensor in GIT repository, e.g. \"sensor1\".}"
  else
    # Get parameters from script arguments
    init_etc_suricata_rules "$@"
  fi
}
