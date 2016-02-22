# -*- coding: utf-8 -*-

import os
import tempfile

from superdict import SuperDict
from unipath import Path


__here__ = Path(__file__).parent.absolute()

env_var = os.environ.get


PROJECT_NAME = 'bpac'
PROJECT_ROOT = __here__.parent
PACKAGE_ROOT = __here__


# Commons ---------------------------------------------------------------------
DEBUG = int(env_var('DEBUG', 0)) > 0
JSONIFY_PRETTYPRINT_REGULAR = int(env_var('JSONIFY_PRETTYPRINT_REGULAR', 0)) > 0


# Sessions --------------------------------------------------------------------
PERMANENT_SESSION_LIFETIME = 15 * 60


# Logging ---------------------------------------------------------------------
LOG_ROOT = PROJECT_ROOT.child('logs')  # '/var/log/bricata'
LOG_FILE = LOG_ROOT.child('{0}.log'.format(PROJECT_NAME))

SENSOR_LOGGER_NAME = 'sensor'
SENSOR_LOG_FILE = LOG_ROOT.child('{0}-{1}.log'.format(PROJECT_NAME,
                                                      SENSOR_LOGGER_NAME))

LOG_LEVEL = env_var('LOG_LEVEL', 'DEBUG' if DEBUG else 'INFO').upper()
LOG_FORMAT = env_var(
    'LOG_FORMAT',
    '%(levelname)-8s [%(asctime)s] %(name)s:%(lineno)d - %(message)s'
)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'logsna': {
            '()': 'logsna.Formatter',
            'format': LOG_FORMAT,
        }
    },
    'handlers': {
        PROJECT_NAME: {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'maxBytes': 1024 * 1024 * 10,  # 10 MiB
            'backupCount': 10,
            'filename': LOG_FILE,
            'formatter': 'logsna',
        },
        SENSOR_LOGGER_NAME: {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'maxBytes': 1024 * 1024 * 10,  # 10 MiB
            'backupCount': 10,
            'filename': SENSOR_LOG_FILE,
            'formatter': 'logsna',
        },
    },
    'loggers': {
        'app': {
            'handlers': [PROJECT_NAME, ],
            'level': LOG_LEVEL,
        },
        'celery.task': {
            'handlers': [PROJECT_NAME, ],
            'level': LOG_LEVEL,
        },
        SENSOR_LOGGER_NAME: {
            'handlers': [SENSOR_LOGGER_NAME, ],
            'level': LOG_LEVEL,
        },
    },
}


# DB --------------------------------------------------------------------------
DB_DIALECT = env_var('DB_DIALECT', 'mysql')
DB_ADDRESS = env_var('DB_ADDRESS', 'localhost')

DB_USER = env_var('DB_USER', 'root')
DB_PASSWORD = env_var('DB_PASSWORD', '')

PRIMARY_DB_NAME = env_var('PRIMARY_DB_NAME', PROJECT_NAME)
SNORBY_DB_NAME = env_var('ORIGINAL_DB_NAME', 'bricata')

DB_ENGINE_URI = (
    "{dialect}://{user}:{password}@{address}"
    .format(dialect=DB_DIALECT,
            address=DB_ADDRESS,
            user=DB_USER,
            password=DB_PASSWORD))

DATABASE_URI_FORMAT = "{engine_uri}/{{name}}".format(engine_uri=DB_ENGINE_URI)

SQLALCHEMY_DATABASE_URI = DATABASE_URI_FORMAT.format(name=PRIMARY_DB_NAME)
SQLALCHEMY_BINDS = {
    'snorby': DATABASE_URI_FORMAT.format(name=SNORBY_DB_NAME),
}

SQLALCHEMY_MIGRATE_REPO = PROJECT_ROOT.child('app', 'db', 'migrations')


# Redis -----------------------------------------------------------------------
REDIS_DBS_OFFSET = env_var('REDIS_DBS_OFFSET', 0)
REDIS_DBS = SuperDict({
    'CELERY': REDIS_DBS_OFFSET + 1,
    'CELERY_RESULTS': REDIS_DBS_OFFSET + 2,
    'CACHE': REDIS_DBS_OFFSET + 3,
    # 'SESSIONS': REDIS_DBS_OFFSET + 4,
})

REDIS_HOST = env_var('REDIS_HOST', 'localhost')
REDIS_PORT = env_var('REDIS_PORT', 6379)
REDIS_PASSWORD = env_var('REDIS_PASSWORD', '')

REDIS_DB_URI_TEMPLATE = '{protocol}://{host}:{port}/{{db}}'.format(
    protocol='redis',
    host=REDIS_HOST,
    port=REDIS_PORT,
)


# Caching ---------------------------------------------------------------------
CACHE_ENABLED = env_var('CACHE_ENABLED')
CACHE_ENABLED = (int(CACHE_ENABLED) > 0
                 if CACHE_ENABLED is not None else
                 not DEBUG)

CACHE_TYPE = 'redis' if CACHE_ENABLED else 'null'
CACHE_NO_NULL_WARNING = True
CACHE_KEY_PREFIX = PROJECT_NAME + ':'
CACHE_REDIS_URL = REDIS_DB_URI_TEMPLATE.format(db=REDIS_DBS.CACHE)


# Celery ----------------------------------------------------------------------
CELERY_STORE_ERRORS_EVEN_IF_IGNORED = True
CELERY_TASK_RESULT_EXPIRES = 60 * 60 * 24  # Store results for 24 hours
CELERY_DISABLE_RATE_LIMITS = True
CELERY_TRACK_STARTED = True
CELERY_IMPORTS = ()

CELERY_TASK_SERIALIZER = 'pickle'
CELERY_RESULT_SERIALIZER = CELERY_TASK_SERIALIZER
CELERY_ACCEPT_CONTENT = [CELERY_TASK_SERIALIZER, ]

CELERY_BROKER_URL = REDIS_DB_URI_TEMPLATE.format(
    db=REDIS_DBS.CELERY,
)
CELERY_RESULT_BACKEND = REDIS_DB_URI_TEMPLATE.format(
    db=REDIS_DBS.CELERY_RESULTS,
)

# FUTURE:
#     Increase number of workers as needed, but route
#     'InvokePolicyApplicationGroupTask' to a single worker, because
#     this task MUST NOT be executed in parallel.
CELERYD_CONCURRENCY = 1
CELERYD_MAX_TASKS_PER_CHILD = 100

CELERYBEAT_MAX_LOOP_INTERVAL = 60
CELERYBEAT_SCHEDULE = {
}


# SSH -------------------------------------------------------------------------
SSH_DEFAULTS = SuperDict({
    'PORT': 22,
    'CONN_TIMEOUT': 30.0,
    'EXEC_TIMEOUT': 5 * 60,

    'KEYS_ROOT': PROJECT_ROOT.child('ssh'),
    'PRIVATE_KEY': {
        'LENGTH': 2048,
        'PASSWORD': None,
    },
})

SSH_KEYS_ROOT = env_var('SSH_KEYS_ROOT', SSH_DEFAULTS.KEYS_ROOT)


# Communication with sensors --------------------------------------------------
SENSOR_SSH_DEFAULTS = SuperDict({
    'PORT': env_var(
        'SENSOR_SSH_DEFAULT_PORT', SSH_DEFAULTS.PORT,
    ),
    'CONN_TIMEOUT': env_var(
        'SENSOR_SSH_DEFAULT_CONN_TIMEOUT', SSH_DEFAULTS.CONN_TIMEOUT
    ),
    'EXEC_TIMEOUT': env_var(
        'SENSOR_SSH_DEFAULT_EXEC_TIMEOUT', SSH_DEFAULTS.EXEC_TIMEOUT
    ),
    'PRIVATE_KEY': dict(SSH_DEFAULTS.PRIVATE_KEY, **{
        'FILENAME': 'sensor.key',
    })
})

# WARNING!
# Sensitive defaults MUST be kept in environment outside codebase!
# Branch with Django is already doing so.
SENSOR_AUTH = SuperDict({
    'PASSWORD': {
        'USERNAME': env_var('SENSOR_AUTH_PASSWORD_USERNAME', 'bricata'),
        'PASSWORD': env_var('SENSOR_AUTH_PASSWORD_PASSWORD', 'Br!C@ta2015'),
    },
    'PRIVATE_KEY': {
        'USERNAME': env_var('SENSOR_AUTH_PRIVATE_KEY_USERNAME', 'cmcadmin'),
        'FILENAME': env_var(
            'SENSOR_AUTH_PRIVATE_KEY_FILENAME',
            SSH_KEYS_ROOT.child(SENSOR_SSH_DEFAULTS.PRIVATE_KEY.FILENAME)
        ),
        'PASSWORD': env_var(
            'SENSOR_AUTH_PRIVATE_KEY_PASSWORD',
            SENSOR_SSH_DEFAULTS.PRIVATE_KEY.PASSWORD
        ),
    },
})

SENSOR_COMMANDS = SuperDict({
    'TAKE_CONTROL_MANUALLY': {
        'COMMAND': env_var(
            'SENSOR_COMMAND_TAKE_CONTROL_MANUALLY',
            "curl -sSL https://cmc/get/conf.sh | bash"
        ),
    },
    'GENERATE_INITIALIZER': {
        'COMMAND': env_var(
            'SENSOR_COMMAND_GENERATE_INITIALIZER',
            "/usr/bin/sensor-provisioning-init_sensor.sh",
        ),
    },
    'SSH': {
        'LIST_INTERFACES': {
            'COMMAND': env_var(
                'SENSOR_COMMAND_SSH_LIST_INTERFACES',
                "/usr/bin/net_interfaces.py"
            ),
            'CONN_TIMEOUT': env_var(
                'SENSOR_COMMAND_SSH_LIST_INTERFACES_CONN_TIMEOUT',
                SENSOR_SSH_DEFAULTS.CONN_TIMEOUT
            ),
            'EXEC_TIMEOUT': env_var(
                'SENSOR_COMMAND_SSH_LIST_INTERFACES_EXEC_TIMEOUT',
                SENSOR_SSH_DEFAULTS.EXEC_TIMEOUT
            ),
        },
        'TAKE_CONTROL': {
            'COMMAND': env_var(
                'SENSOR_COMMAND_SSH_TAKE_CONTROL',
                "/usr/bin/sensor-provisioning-init_sensor.sh"
            ),
            'CONN_TIMEOUT': env_var(
                'SENSOR_COMMAND_SSH_TAKE_CONTROL_CONN_TIMEOUT',
                SENSOR_SSH_DEFAULTS.CONN_TIMEOUT
            ),
            'EXEC_TIMEOUT': env_var(
                'SENSOR_COMMAND_SSH_TAKE_CONTROL_EXEC_TIMEOUT',
                10 * 60
            ),
        },
        'PULL_N_APPLY_RULES': {
            'COMMAND': env_var(
                'SENSOR_COMMAND_SSH_PULL_N_APPLY_RULES',
                "/usr/bin/ids-update-rules-v160.sh"
            ),
            'CONN_TIMEOUT': env_var(
                'SENSOR_COMMAND_SSH_PULL_N_APPLY_RULES_CONN_TIMEOUT',
                SENSOR_SSH_DEFAULTS.CONN_TIMEOUT
            ),
            'EXEC_TIMEOUT': env_var(
                'SENSOR_COMMAND_SSH_PULL_N_APPLY_RULES_EXEC_TIMEOUT',
                SENSOR_SSH_DEFAULTS.EXEC_TIMEOUT
            ),
        },
    },
})


# File uploading --------------------------------------------------------------
MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MiB


# Rules -----------------------------------------------------------------------
RULES_DEFAULTS = SuperDict({
    'CATEGORY_NAME': env_var('RULES_DEFAULT_CATEGORY_NAME', "Imported"),
    'SEVERITY_NAME': env_var('RULES_DEFAULT_SEVERITY_NAME', "Medium"),
    'REPO': {
        'USER': {
            'NAME': "CMC",
            'EMAIL': "cmc@cmc.bricata.com",
        },
        'LOCAL': {
            'URI': Path(tempfile.gettempdir(),
                        '-'.join([PROJECT_NAME, "sensor", "rules", ])),
        },
        'REMOTE': {
            'NAME': "origin",
            'URI': "/var/www/git/rules.git",
        }
    }
})

RULES_PRIMARY_FILE_EXTENSION = 'rules'
RULES_ALLOWED_EXTENSIONS = set([RULES_PRIMARY_FILE_EXTENSION, 'rule', ])
RULES_REPO = SuperDict({
    'USER': {
        'NAME': env_var(
            'RULES_REPO_USER_NAME', RULES_DEFAULTS.REPO.USER.NAME
        ),
        'EMAIL': env_var(
            'RULES_REPO_USER_EMAIL', RULES_DEFAULTS.REPO.USER.EMAIL
        ),
    },
    'LOCAL': {
        'URI': env_var('RULES_REPO_LOCAL_URI', RULES_DEFAULTS.REPO.LOCAL.URI),
    },
    'REMOTE': {
        'NAME': env_var(
            'RULES_REPO_REMOTE_NAME', RULES_DEFAULTS.REPO.REMOTE.NAME
        ),
        'URI': env_var(
            'RULES_REPO_REMOTE_URI', RULES_DEFAULTS.REPO.REMOTE.URI
        ),
    }
})


# Class types -----------------------------------------------------------------
RULE_CLASS_TYPES_PRIMARY_FILE_EXTENSION = 'config'
RULE_CLASS_TYPES_ALLOWED_EXTENSIONS = set([
    RULE_CLASS_TYPES_PRIMARY_FILE_EXTENSION,
])


# Reference types -------------------------------------------------------------
RULE_REFERENCE_TYPES_PRIMARY_FILE_EXTENSION = 'config'
RULE_REFERENCE_TYPES_ALLOWED_EXTENSIONS = set([
    RULE_REFERENCE_TYPES_PRIMARY_FILE_EXTENSION,
])
