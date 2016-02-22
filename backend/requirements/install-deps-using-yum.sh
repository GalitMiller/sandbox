#!/bin/bash

# To run backend
sudo yum install -y \
  python-flask-restless-0.17.1dev \
  python-flask-0.10.1 \
  python-flask-cache-0.13.1 \
  python-flask-celery-helper-1.1.0 \
  python-flask-login-0.2.11 \
  python-flask-sqlalchemy-2.0 \
  MySQL-python-1.2.5 \
  python-sqlalchemy-0.9.9 \
  python-sqlalchemy-continuum-1.1.5 \
  python-sqlalchemy-utils-0.30.0 \
  python-sqlalchemy-migrate-0.9.6 \
  python-awesome-slugify-1.6.4 \
  python-celery-3.1.17 \
  python-colour-0.1.1 \
  GitPython-1.0.1 \
  python-inflection-0.3.1 \
  python-isotopic-logging-1.0.1 \
  python-logsna-1.2 \
  python-netifaces-0.10.4 \
  python-paramiko-1.15.2 \
  python-pyasn1-0.1.7 \
  python-redis-2.10.3 \
  python-schematics-1.0.4 \
  python-scp-0.10.0 \
  python-superdict-1.0.3 \
  python-twisted-15.1.0 \
  python-unipath-1.1 \
  bpython-0.13 \
  python-flask-script-2.0.5 \
  pylint-1.4.3


# To test backend
sudo yum install -y \
  python-invoke-0.9.0 \
  python-dateutil \
  python-mimerender \
  python-nose \
  python-nose-exclude \
  python-tempita \
  python-freezegun \
  python-sqlparse \
  python-mock
