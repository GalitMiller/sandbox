#!/bin/bash
set -ue

# Script to restore MySQL dump at KICKSTART TIME.

DUMP="${1:?Argument required: path to file with gzipped SQL dump to restore, e.g. \"/var/lib/bricata/mysql-dump/cmc-db.sql.gz\".}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if mysql -u root -e 'select now();' >/dev/null 2>&1
then
  echo "ERROR: MySQL server is already running. If you really need to restore dump to live server, just execute command \"zcat '$DUMP' | mysql -u root\"." >&2
  exit 1
fi

# Prepare database internal tables
bash -x /usr/bin/mysql_install_db

# Run MySQL server manually in background
mkdir -p /var/run/mysqld
chown -R mysql.mysql /var/run/mysqld
/usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib64/mysql/plugin --user=mysql &
#/usr/libexec/mariadb-wait-ready

# Restore dump
zcat "$DUMP" | mysql -u root

# Stop server
kill %1
wait %1
