#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sys
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

from flask.ext.script import Manager
from inflection import underscore
from slugify import slugify

from app import app
from app.utils.encoding import smart_str
from app.utils.modules import autodiscover


def add_management_commands(root):
    modules = autodiscover('management', app.config['PACKAGE_ROOT'])

    for module in modules:
        commands = getattr(module, '__all__', None)

        if not commands:
            continue

        namespace = getattr(module, '__namespace__', None)
        if namespace:
            manager = Manager(usage=module.__doc__.strip())
            root.add_command(namespace, manager)
        else:
            manager = root

        for command_name in commands:
            command = getattr(module, command_name)
            name = getattr(command, 'name', command_name)
            manager.add_command(underscore(slugify(name)), command)


def add_stdout_log_handler():
    formatter = logging.Formatter("%(levelname)-8s %(message)s")

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.setLevel(app.config['LOG_LEVEL'])

    root_logger = logging.getLogger()
    root_logger.addHandler(handler)


def is_default_command_called(manager):
    try:
        command_name = smart_str(sys.argv[1])
    except IndexError:
        return False
    else:
        return command_name in manager._commands


def main():
    manager = Manager(app)
    # Excplicitly add default commands before 'Manager.handle()' is called
    manager.add_default_commands()

    if not is_default_command_called(manager):
        add_management_commands(manager)
        add_stdout_log_handler()

    manager.run()


if __name__ == "__main__":
    main()
