# -*- coding: utf-8 -*-

import os

from paramiko import RSAKey

from app.config import SSH_DEFAULTS


def generate_private_key(filename, length=None, password=None):
    length = length or SSH_DEFAULTS.PRIVATE_KEY.LENGTH
    password = password or SSH_DEFAULTS.PRIVATE_KEY.PASSWORD

    key = RSAKey.generate(bits=length)
    key.write_private_key_file(filename=filename, password=password)


def generate_public_key_from_private_key(filename, password=None):
    key = RSAKey(filename=filename, password=password)

    with open("{0}.pub".format(filename), 'w') as f:
        f.write("{0} {1}".format(key.get_name(), key.get_base64()))


def generate_both_keys(filename, length=None, password=None):
    length = length or SSH_DEFAULTS.PRIVATE_KEY.LENGTH
    password = password or SSH_DEFAULTS.PRIVATE_KEY.PASSWORD

    generate_private_key(filename, length, password)
    generate_public_key_from_private_key(filename, password)


def ensure_private_key(filename):
    if not os.path.exists(filename):
        generate_private_key(filename)
