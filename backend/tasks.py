# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from invoke import task, run
from superdict import SuperDict

from app.config import LOG_FILE, PROJECT_NAME, SENSOR_LOG_FILE


env = SuperDict()
env.project_name = PROJECT_NAME
env.logs = {
    'flask': LOG_FILE,
    'nginx': "/var/log/nginx/error.log",
    'sensor': SENSOR_LOG_FILE,
    # 'celeryd': "/var/log/celery/{project_name}-w1.log".format(**env),
    # 'celerybeat': "/var/log/celery/beat-{project_name}.log".format(**env),
}


@task
def lint():
    """
    Lint Python modules.
    """
    run("pylint --rcfile=.pylintrc {package_name}/; echo".format(**env))


@task(help={
    'service': "name of service whose log you whant to see. "
               "Available values: {0}".format(', '.join(env.logs.keys())),
})
def log(service='flask'):
    """
    Output log to console.
    Examples:
        inv log
        inv log -s flask
    """
    if service in env.logs.keys():
        run("tail -f {0}".format(env.logs[service]))
    else:
        raise ValueError("Unknown service '{0}'!".format(service))


@task
def clean():
    """
    Remove Python cache files.
    """
    run("find . -name '*.pyc' -exec rm -rf {} \;")


@task(pre=[clean, ])
def test():
    """
    Run tests.
    """
    run("coverage run `which nosetests` -v --nocapture --with-doctest ./app")
    run("coverage report -m")
    clean()
