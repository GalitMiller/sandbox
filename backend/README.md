# Bricata ProAccel Configuration Management Console backend

Backend is written in python 2.7 using flask, flask-restless and SQLAlchemy.


## Installation

Install necessary system packages:

    yum install git npm python-pip make glibc-devel python-devel python-virtualenv

Run `./setup.sh` to install necessary modules in virtual environment in
`./flask`, then run `./enter.sh` or `. flask/bin/activate`
to prepend `./flask/bin` to `PATH` variable.

Alternatively, you can use system python and install required modules using
system tools or using command `pip install -r ./requirements/all.txt`.

Run `./manage.py db create` to recreate database.


## Upgrade datase

Run `./manage.py db upgrade head -d ./app/db/migrations` to upgrade database to latest version.


## Management

You can execute different auxiliary management commands.


### via manage.py

One way is to use `manage.py`. Use `--help` argument to get list of avaivable
commands or command groups:

    ./manage.py --help

You can get help on particular command or group as well, e.g.:

    ./manage.py runserver --help
    ./manage.py data --help
    ./manage.py data create_sensor --help


### via Invoke

You can use Invoke for some other tasks also. First of all, see the list of
available commands:

    inv --list

Of course, you can get help for commands, e.g.:

    inv --help log


## Running

Run `./manage.py runserver --no-debug` in production environment,
or `./manage.py runserver` in development environment.


## Development

Run `./manage.py db prepopulate` to populate database with initial data.

If you need to have extra data, add '-x' option: `./manage.py db prepopulate -x`.

Run `./manage.py db migrate` to create diff between database and model and
store it as new version in `./app/db/migrations`.

To start web server run `./manage.py runserver`.


## Testing

To run tests execute the following:

    python -m unittest discover

If you have `nose` and `coverage` installed (`requirements/tests.txt`) you can
simply run:

    nosetests

or:

    inv test

The latter will additionally give you report about code coverage.
