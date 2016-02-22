#!/bin/bash
set -ue

# Script to execute at first boot of docker container

# Function to upgrade database to latest schema version, when necessary.
upgade_database() {
  # Try to create alembic_version table, when it is not exists, so upgrade from 1.5.1 to 1.5.2+ will work.
  mysql -u root < /var/www/app/app/db/sql/scripts/init_migration_table.sql >/dev/null 2>&1 || :

  bpac-manage.sh db upgrade head || {
    echo "ERROR: Cannot upgrade bpac database using command \"bpac-manage.sh db upgrade head\"." >&2
    return 1
  }

  bpac-rake.sh db:migrate || {
    echo "ERROR: Cannot upgrade bricata database using command \"bpac-rake.sh db:migrate\"." >&2
    return 1
  }
}

# Try to upgrade database or create it from scratch, when it is not initialized yet.
if ! upgade_database
then
  if [ -f /var/lib/mysql/bricata-db-reset ]
  then
    echo "ERROR: Cannot upgrade database, but database is already initialized. It looks like database is damaged, or incompatible, or bug in the code. Remove file \"/var/lib/mysql/bricata-db-reset\" to perform full reset of database." >&2
    exit 1
  else
    echo "INFO: Cannot upgrade database, but it looks like database is not initialized yet. Initializing..."
    bpac-setup-database.sh || {
      echo "ERROR: Cannot initialize database."
      exit 1
    }
  fi
fi
