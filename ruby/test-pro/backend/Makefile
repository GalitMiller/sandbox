#!/usr/bin/make -f

PYTHON=python

# Application currently has nothing to build, so execute unit test cases only
all: test

# Setup local virtual environment for python and modules
virt-setup:
	./setup.sh

# Create user root with password 'bricata', which is accessible from outside
remote_db_user:
	# Drop existing user, if any
	mysql -u root --database=mysql --execute 'drop user "root"@"%";' || :
	# Create new user with proper password
	mysql -u root --database=mysql --execute 'create user "root"@"%" identified by "bricata"; grant all on *.* to "root"@"%" with grant option; flush privileges;'

# Create database schema or upgrate it to latest version if it is already created
database:
	$(PYTHON) ./manage.py db create || $(PYTHON) ./manage.py db upgrade head -d ./app/db/migrations

# Put initial data into database
initial_data:
	$(PYTHON) ./manage.py db prepopulate

# Execute unit test cases
test:
	#inv test
	nosetests -v

# Run application localy in debug mode
run:
	$(PYTHON) ./manage.py runserver

# Run application localy in production-like mode
run-prod:
	$(PYTHON) ./manage.py runserver --no-debug

clean:
	find -name '*.pyc' -exec rm -f '{}' '+'
	find -name '*.py0' -exec rm -f '{}' '+'
	rm -f logs/*

dist-clean: clean
	rm -rf ./flask

.PHONY: all setup database mock_data test clean clean-dist
