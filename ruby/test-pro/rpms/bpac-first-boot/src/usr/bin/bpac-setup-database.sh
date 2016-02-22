#!/bin/bash
set -ue

# This script must be executed once to create (or reset) database.

if [ -f /var/lib/mysql/bricata-db-reset ]
then
  echo "INFO: Database is already initialized. Remove file \"/var/lib/mysql/bricata-db-reset\" to perform full reset of database." >&2
  exit 0
fi

echo "INFO: Performing reset of database (bricata and bpac)."

# Run rake setup (hard reset) over the Bricata/Snorby application if is was not initialized
bpac-rake.sh bricata:hard_reset || {
  echo "ERROR: Cannot recreate bricata database using command \"bpac-rake.sh bricata:hard_reset\"." >&2
  exit 1
}

# (Re)create database
bpac-manage.sh db recreate || {
  echo "ERROR: Cannot recreate bpac database using command \"bpac-manage.sh db recreate\"." >&2
  exit 1
}

# TODO: FIXME: remove hardcoded passwords, move it to configuration file and autogenerate at first run.
# Grant privileges to 'root' and 'bricata' users to connect to 'bricata' DB from sensors.
# For compatibility with older sensors, AFAIK
mysql -u root --database=bricata --execute  "GRANT ALL PRIVILEGES ON bricata.* TO 'root'@'%' IDENTIFIED BY 'bricata';" || {
  echo "ERROR: Cannot grant access to bricata database for remote user root with hardcoded password." >&2
  exit 1
}
# For new sensors, AFAIK
mysql -u root --database=bricata --execute  "GRANT ALL PRIVILEGES ON bricata.* TO 'bricata'@'%' IDENTIFIED BY 'br1c@t@';" || {
  echo "ERROR: Cannot grant access to bricata database for remote user bricata with hardcoded password." >&2
  exit 1
}

# Seed bpac database with initial data
bpac-manage.sh db prepopulate || {
  echo "ERROR: Cannot prepopulate bpac database using command \"bpac-manage.sh db prepopulate\"." >&2
  exit 1
}

# Enable user accounts sync between Snorby and ProAccel databases (BPAC-313, BPAC-412):
bpac-manage.sh users sync_setup || {
  echo "ERROR: Cannot setup synchronization of user accounts between bricata and bpac databases using command \"bpac-manage.sh users sync_setup\"." >&2
  exit 1
}
bpac-manage.sh users sync || {
  echo "ERROR: Cannot synchronize user accounts between bricata and bpac databases using command \"bpac-manage.sh users sync\"." >&2
  exit 1
}

# Enable sensors sync between Snorby and ProAccel databases (BPAC-359):
bpac-manage.sh sensors sync_setup || {
  echo "ERROR: Cannot setup synchronization of sensors between bricata and bpac databases using command \"bpac-manage.sh sensors sync_setup\"." >&2
  exit 1
}
bpac-manage.sh sensors sync || {
  echo "ERROR: Cannot setup synchronization of sensors between bricata and bpac databases using command \"bpac-manage.sh sensors sync\"." >&2
  exit 1
}

touch /var/lib/mysql/bricata-db-reset || {
  echo "ERROR: cannot create file \"bricata-db-reset\" in \"/var/lib/mysql\" directory." >&2
  exit 1
}
echo "INFO: database is reset to initial state."
