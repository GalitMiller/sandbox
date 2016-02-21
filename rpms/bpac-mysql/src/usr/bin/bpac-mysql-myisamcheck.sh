#!/bin/sh
set -ue

# Change owner of /var/lib/mysql to mysql, otherwise mysqld will not start.
# Such situation happens when /var/lib/mysql directory is mounted into container for first time.
chown -R mysql.mysql /var/lib/mysql

# Fix problems with MySQL ISA databases, if any. Shutdown container properly to avoid them.
# myisamchk does not require mysql server to be ran.
myisamchk --silent --force --fast --update-state  /var/lib/mysql/*/*.MYI || {
  echo "WARNING: Cannot repair mysql database. Maybe there is no database at all (empty directory) or it damaged beyond repair."
}
