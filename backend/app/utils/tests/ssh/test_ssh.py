# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import paramiko
import tempfile
import unittest
import uuid

from unipath import Path

from app.config import SSH_KEYS_ROOT
from app.utils import ssh

from .mock_server import start_threaded_server, stop_threaded_server


class SSHConnectionTestCase(unittest.TestCase):

    username = 'mock-user'
    listen_interface = 'localhost'
    listen_port = 0

    @classmethod
    def setUpClass(cls):
        cls.server_private_key = SSH_KEYS_ROOT.child('mock-server')
        cls.client_private_key = SSH_KEYS_ROOT.child(cls.username)

        ssh.generate_both_keys(cls.server_private_key)
        ssh.generate_both_keys(cls.client_private_key)

        cls.peer = start_threaded_server(interface=cls.listen_interface,
                                         port=cls.listen_port,
                                         username=cls.username,
                                         keys_path=SSH_KEYS_ROOT)

    @classmethod
    def tearDownClass(cls):
        stop_threaded_server()
        try:
            os.remove(cls.server_private_key)
            os.remove(cls.server_private_key + '.pub')
            os.remove(cls.client_private_key)
            os.remove(cls.client_private_key + '.pub')
        except OSError as e:
            print("Failed to cleanup SSH keys: {e}".format(e=e))

    def setUp(self):
        filename = self.client_private_key
        rsa_key = paramiko.RSAKey.from_private_key_file(filename)

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.peer.host, self.peer.port,
                            username=self.username,
                            pkey=rsa_key)

    def tearDown(self):
        self.client.close()

    def test_whoami(self):
        stdin, stdout, stderr = self.client.exec_command('whoami')
        output = stdout.read().strip()
        self.assertEqual(output, self.username)

    def test_echo(self):
        stdin, stdout, stderr = self.client.exec_command("echo foo bar baz")
        output = stdout.read().strip()
        self.assertEqual(output, "foo bar baz")

    def test_invalid_arguments(self):
        stdin, stdout, stderr = self.client.exec_command("whoami today")
        output = stdout.read().strip()
        self.assertEqual(output, "Error: exec_whoami() takes exactly 1 argument (2 given)")

    def test_unknown_command(self):
        stdin, stdout, stderr = self.client.exec_command("wrong command")
        output = stdout.read().strip()
        self.assertEqual(output, "No such command.")


class SSHHelpersTestCase(unittest.TestCase):

    @staticmethod
    def generate_filename():
        return Path(tempfile.gettempdir(), str(uuid.uuid4()))

    def test_generate_ssh_private_key(self):
        filename = self.generate_filename()
        self.assertFalse(os.path.exists(filename))

        ssh.generate_private_key(filename)
        self.assertTrue(os.path.exists(filename))

        private_key = paramiko.RSAKey.from_private_key_file(filename)
        self.assertEqual(private_key.get_name(), 'ssh-rsa')

        try:
            os.remove(filename)
        except OSError:
            pass

    def test_create_ssh_public_key_from_private_key(self):
        filename = self.generate_filename()
        filename_pub = filename + '.pub'

        ssh.generate_private_key(filename)

        self.assertFalse(os.path.exists(filename_pub))
        ssh.generate_public_key_from_private_key(filename)
        self.assertTrue(os.path.exists(filename_pub))

        expected = paramiko.RSAKey(filename=filename).get_base64()

        with open(filename_pub, 'r') as f:
            actual = f.read().split(None, 1)[1]

        self.assertEqual(actual, expected)
