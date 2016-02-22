# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import logging
import os
import paramiko
import tempfile

from flask import json
from isotopic_logging import autoprefix_injector
from scp import SCPClient
from subprocess import Popen, PIPE
from unipath import Path

from app.config import SENSOR_COMMANDS, SENSOR_LOGGER_NAME, SENSOR_AUTH
from app.utils import six
from app.utils.encoding import smart_str

from .exceptions import TakeControlOverSensorError, SensorIsAlreadyUnderControl
from .utils import connect_n_exec_sensor_command, exec_sensor_command


LOG = logging.getLogger(__name__)
SENSOR_LOG = logging.getLogger(SENSOR_LOGGER_NAME)


def fetch_sensor_interfaces(sensor, conn_timeout=None, exec_timeout=None):
    if conn_timeout is None:
        conn_timeout = SENSOR_COMMANDS.SSH.LIST_INTERFACES.CONN_TIMEOUT

    if exec_timeout is None:
        exec_timeout = SENSOR_COMMANDS.SSH.LIST_INTERFACES.EXEC_TIMEOUT

    with autoprefix_injector() as inj:
        LOG.debug(inj.mark(
            "Getting actual list of interfaces at '{sensor.name}' "
            "({sensor.hostname})"
            .format(sensor=sensor)))

        try:
            output = connect_n_exec_sensor_command(
                sensor,
                SENSOR_COMMANDS.SSH.LIST_INTERFACES.COMMAND,
                conn_timeout,
                exec_timeout,
            )
        except Exception as e:
            LOG.error(inj.mark(
                "Failed to get list of interfaces: {e}".format(e=e)))
            return {}

        try:
            infos = json.loads(output)
        except Exception as e:
            LOG.error(inj.mark(
                "Failed to read information about interfaces: {e}"
                .format(e=e)))
            return {}

        # TODO: what if there is more than 1 link info?
        interfaces = {
            x['link'][0]['addr'].upper(): x['name']
            for x in infos
        }

        LOG.debug(inj.mark(
            "Got interfaces: {0}".format(interfaces)))

        return interfaces


class TakeControlOverSensor(object):

    def __call__(self, sensor, remote_username=None, remote_password=None,
                 conn_timeout=None, exec_timeout=None):
        self.sensor = sensor
        self._ensure_sensor_is_not_under_control()

        self.remote_username = (remote_username
                                if remote_username is not None else
                                SENSOR_AUTH.PASSWORD.USERNAME)
        self.remote_password = (remote_password
                                if remote_username is not None else
                                SENSOR_AUTH.PASSWORD.PASSWORD)
        self.conn_timeout = (conn_timeout
                             if conn_timeout is not None else
                             SENSOR_COMMANDS.SSH.TAKE_CONTROL.CONN_TIMEOUT)
        self.exec_timeout = (exec_timeout
                             if exec_timeout is not None else
                             SENSOR_COMMANDS.SSH.TAKE_CONTROL.EXEC_TIMEOUT)

        with autoprefix_injector() as inj:
            LOG.info(inj.mark(
                "Taking control over sensor '{sensor.name}' "
                "({sensor.hostname})..."
                .format(sensor=sensor)))

            self._inject_initializer_filename()
            generate_sensor_initializer(self.filename)

            try:
                self._send_n_invoke_initializer()
            except TakeControlOverSensorError as e:
                LOG.error(inj.mark(
                    "Failed:\n{e}".format(e=e)))
                raise e
            else:
                LOG.info(inj.mark("Success"))
            finally:
                os.remove(self.filename)

    def _ensure_sensor_is_not_under_control(self):
        if self.sensor.is_controlled_by_cmc:
            raise SensorIsAlreadyUnderControl(
                "Sensor \"{name}\" is already under CMC control"
                .format(name=self.sensor.name))

    def _inject_initializer_filename(self):
        timestamp = datetime.datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S_%f")
        self.filename = Path(tempfile.gettempdir(),
                             "sensor_initializer_{0}".format(timestamp))

        with autoprefix_injector() as inj:
            LOG.debug(inj.mark(
                "Using '{filename}' to temporally store generated "
                "initializer"
                .format(filename=self.filename)))

    def _send_n_invoke_initializer(self):
        with autoprefix_injector() as inj:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            LOG.debug(inj.mark(
                "Connecting to '{hostname}:{port}' as '{username}' "
                "(timeout: {timeout} sec)"
                .format(
                    hostname=self.sensor.hostname,
                    port=self.sensor.ssh_port,
                    username=self.remote_username,
                    timeout=self.conn_timeout)))

            self.ssh.connect(hostname=self.sensor.hostname,
                             port=self.sensor.ssh_port,
                             username=self.remote_username,
                             password=self.remote_password,
                             allow_agent=False,
                             look_for_keys=False,
                             timeout=self.conn_timeout)

            try:
                self._send_initializer()
                self._invoke_initializer()
            finally:
                self.ssh.close()

    def _send_initializer(self):
        with autoprefix_injector() as inj:
            LOG.debug(inj.mark("Sending initializer to sensor..."))

            scp = SCPClient(self.ssh.get_transport())
            scp.put(self.filename, self.filename)

            LOG.debug(inj.mark("Initializer was successfully sent to sensor"))

    def _invoke_initializer(self):
        command = " && ".join([
            "sudo bash {filename}",
            "rm -f {filename}",
        ]).format(filename=self.filename)

        with autoprefix_injector() as inj:
            LOG.debug(inj.mark(
                "Invoking initializer via command '{command}'..."
                .format(command=command)))

            try:
                exec_sensor_command(self.ssh, command, self.exec_timeout)
            except Exception as e:
                six.reraise(TakeControlOverSensorError, e.message)


take_control_over_sensor = TakeControlOverSensor()


def generate_sensor_initializer(destination=None):
    with autoprefix_injector() as inj:
        LOG.debug(inj.mark(
            "Generating sensor initializer with output to "
            "'{destination}'..."
            .format(destination=destination or "STDOUT")))

        command = [
            SENSOR_COMMANDS.GENERATE_INITIALIZER.COMMAND,
            'generate',
            destination or '-'
        ]
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            raise RuntimeError(smart_str(stderr))

        LOG.debug(inj.mark("Sensor initializer was successfully generated"))
        return smart_str(stdout)
