#!/bin/sh
set -ue

# Fix problems with MySQL databases, if any. m
mysqlcheck --auto-repair --all-databases || {
  echo "WARNING: Cannot repair mysql database using command \"mysqlcheck --auto-repair --all-databases\". Maybe there is no database at all (empty directory) or it damaged beyond repair."
}
