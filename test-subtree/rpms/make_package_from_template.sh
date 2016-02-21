#!/bin/bash
set -ue
BIN_DIR="$(readlink -f "$(dirname "$0" )" )" #"
TEMPLATE_DIR="$BIN_DIR/bpac-TEMPLATE"

# Make package directory from template directory.
make_package_from_template() {
  local PACKAGE="${1:?Argument is required: name of package to use in place of TEMPLATE placeholder, e.g. \"foo-bar\", so full package name will be \"bpac-foo-bar\".}"

  local PACKAGE_DIR="$BIN_DIR/bpac-$PACKAGE"


  [ ! -e "$PACKAGE_DIR" ] || {
    echo "ERROR: Directory \"$PACKAGE_DIR\" is already exists, cannot overwrite it." >&2
    return 1
  }

  # Create copy of package
  cp -ra "$TEMPLATE_DIR" "$PACKAGE_DIR" || {
    echo "ERROR: Cannot copy from directory \"$TEMPLATE_DIR\" to \"$PACKAGE_DIR\" directory." >&2
    return 1
  }

  # Rename all *TEMPLATE* files to *PACKAGE*
  find "$PACKAGE_DIR" -type f -exec rename "TEMPLATE" "$PACKAGE" '{}' '+'

  # Rename all .sample files to strip suffix
  find "$PACKAGE_DIR" -type f -exec rename ".sample" "" '{}' '+'

  # Replace TEMPLATE string by PACKAGE in all files
  find "$PACKAGE_DIR" -type f -exec sed -i "s/TEMPLATE/$PACKAGE/" '{}' '+'

  # Show TODO's and allow to edit or enter value to replace
  echo "INFO: Fill TODO's or or press enter to leave as is or press ^C to abort:"
  local IFS=$'\n'
  local I
  for I in $(grep -ro 'TODO:.*' "$PACKAGE_DIR")
  do
    local FILE="${I%%:TODO:*}" # "/path/file:TODO: descr" -> "/path/file"
    local  DESCR="${I#*:}" # "/path/file:TODO: descr" -> "descr"
    read -re -p "${FILE##*/}: " -i "$DESCR"
    ed -s "$FILE" <<END
/$DESCR/s/$DESCR//
a
$REPLY
.
-1,.j
w
END
  done

}

make_package_from_template "$@"
