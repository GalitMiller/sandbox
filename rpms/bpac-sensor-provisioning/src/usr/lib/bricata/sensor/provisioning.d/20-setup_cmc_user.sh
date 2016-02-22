#!/bin/bash
set -ue

# Create CMC user and add CMC public key to it ~/.ssh/authorized_keys file.

# Store CMC public key in ~/.ssh/authorized_keys
add_public_ket_to_ssh_authorized_keys() {
  local CMC_PUB_KEYS=( "${@:?Argument(s) are required: public key(s) of CMC for SSH in format \"KEY_TYPE BASE64_ENCODED_KEY COMMENT_OR_EMAIL\", e.g. \"ssh-rsa AAAA... CMC public key\".}" )

  mkdir -p "/home/$CMC_USER/.ssh/" || {
    echo "ERROR: Cannot create directory \"/home/$CMC_USER/.ssh/\"." >&2
    return 1
  }

  touch "/home/$CMC_USER/.ssh/authorized_keys" || {
    echo "ERROR: Cannot create file \"/home/$CMC_USER/.ssh/authorized_keys\"." >&2
    return 1
  }

  local CMC_PUB_KEY
  for CMC_PUB_KEY in "${CMC_PUB_KEYS[@]:+${CMC_PUB_KEYS[@]}}"
  do
    # Sanity check: check is public key starts with ssh- and BASE64 start with AAAA (0x00 00 00)
    [[ "$CMC_PUB_KEY" == "ssh-"*  ]] || {
      echo "ERROR: Unexpected format of ssh public key. Example of expected format: \"ssh-rsa AAAAB3NzaC1yc2EA... user@host\". Actual value: \"$CMC_PUB_KEY\"." >&2
    }

    # If key is already found, then do nothing
    ! grep --fixed-strings "$CMC_PUB_KEY" "/home/$CMC_USER/.ssh/authorized_keys" || {
      echo "INFO: Key above is already in \"/home/$CMC_USER/.ssh/authorized_keys\"."
      continue
    }

    sh -c "echo \"$CMC_PUB_KEY\" >>\"/home/$CMC_USER/.ssh/authorized_keys\"" || {
      echo "ERROR: Cannot append public key to \"/home/$CMC_USER/.ssh/authorized_keys\"." >&2
      return 1
    }
  done
}

setup_cmc_user() {
  local CMC_PUB_KEYS=( "${@:?Argument(s) are required: public key(s) of CMC for SSH in format \"KEY_TYPE BASE64_ENCODED_KEY COMMENT_OR_EMAIL\", e.g. \"ssh-rsa AAAA... CMC public key\".}" )
  local CMC_USER="cmcadmin"
  local CMC_GROUP="cmcadmin"
  local CMC_GROUPS=( "adm" "${ADDITIONAL_GROUPS_FOR_CMC_USER[@]:+${ADDITIONAL_GROUPS_FOR_CMC_USER[@]}}" )

  # Create group and user for CMC
  getent group "$CMC_GROUP" >/dev/null || groupadd "$CMC_GROUP" || {
    echo "ERROR: Cannot add group \"$CMC_GROUP\"." >&2
    return 1
  }
  getent passwd "$CMC_USER" >/dev/null || ( IFS=',' ; useradd -g "$CMC_GROUP" --groups "${CMC_GROUPS[*]}" -c "CMC service user" "$CMC_USER" ) || {
    echo "ERROR: Cannot add user \"$CMC_USER\"." >&2
    return 1
  }

  add_public_ket_to_ssh_authorized_keys "${CMC_PUB_KEYS[@]}" || return 1

  chown -R "$CMC_USER.$CMC_GROUP" "/home/$CMC_USER/.ssh/" || {
    echo "ERROR: Cannot change owner of \"/home/$CMC_USER/.ssh/\" directory to user \"$CMC_USER\" and group \"$CMC_GROUP\"." >&2
    return 1
  }

  chmod -R 0700 "/home/$CMC_USER/.ssh/" || {
    echo "ERROR: Cannot change permissions of \"/home/$CMC_USER/.ssh/\" directory to be accessible by owner only." >&2
    return 1
  }

  return 0
}

# Don't execute anything when DEFINE_ONLY variable was set to "yes"
[ "${DEFINE_ONLY:-}" == "yes" ] || {

  if [ "${CONFIG_MODE:-}" == "yes" ] ; then
    # Get parameters from environment variables when in CONFIG_MODE
    setup_cmc_user \
      "${CMC_PUBLIC_KEYS[@]:?Variable is required: CMC_PUBLIC_KEYS: array of public keys of CMC for SSH in format \"KEY_TYPE BASE64_ENCODED_KEY COMMENT_OR_EMAIL\", e.g. \"ssh-rsa AAAA... CMC public key\".}"
  else
    # Get parameters from script arguments
    setup_cmc_user "$@"
  fi
}
