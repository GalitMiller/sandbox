# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import paramiko

from isotopic_logging import autoprefix_injector

from app.config import SENSOR_AUTH, SENSOR_SSH_DEFAULTS, SENSOR_LOGGER_NAME
from app.utils import ssh
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)
SENSOR_LOG = logging.getLogger(SENSOR_LOGGER_NAME)


def connect_n_exec_sensor_command(sensor, command, conn_timeout, exec_timeout):
    # TODO: refactor and make it possible to use username+password

    if conn_timeout is None:
        conn_timeout = SENSOR_SSH_DEFAULTS.CONN_TIMEOUT

    if exec_timeout is None:
        exec_timeout = SENSOR_SSH_DEFAULTS.EXEC_TIMEOUT

    with autoprefix_injector() as inj:
        ssh.ensure_private_key(SENSOR_AUTH.PRIVATE_KEY.FILENAME)
        rsa_key = paramiko.RSAKey.from_private_key_file(
            filename=SENSOR_AUTH.PRIVATE_KEY.FILENAME,
            password=SENSOR_AUTH.PRIVATE_KEY.PASSWORD,
        )

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        LOG.debug(inj.mark(
            "Connecting to '{hostname}:{port}' as user '{username}' using "
            "private key '{key_filename}' (timeout: {timeout} sec)"
            .format(hostname=sensor.hostname,
                    port=sensor.ssh_port,
                    username=SENSOR_AUTH.PRIVATE_KEY.USERNAME,
                    key_filename=SENSOR_AUTH.PRIVATE_KEY.FILENAME,
                    timeout=conn_timeout)))
        client.connect(hostname=sensor.hostname,
                       port=sensor.ssh_port,
                       username=SENSOR_AUTH.PRIVATE_KEY.USERNAME,
                       pkey=rsa_key,
                       timeout=conn_timeout)

        try:
            return exec_sensor_command(client, command, exec_timeout)
        finally:
            client.close()


def exec_sensor_command(client, command, timeout):
    with autoprefix_injector() as inj:
        message = ("Executing raw command '{command}' (timeout: {timeout} sec)"
                   .format(command=command, timeout=timeout))
        LOG.info(inj.mark(message))
        SENSOR_LOG.info(inj.mark(message))

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()

        stdout = smart_str(stdout.read())
        SENSOR_LOG.info(inj.mark(
            "STDOUT:\n{stdout}".format(stdout=stdout)
        ))

        if exit_code == 0:
            return stdout
        else:
            stderr = smart_str(stderr.read())
            SENSOR_LOG.error(inj.mark(
                "STDERR:\n{stderr}".format(stderr=stderr)
            ))
            raise RuntimeError(
                "Command {command} failed with exit code {exit_code}. "
                "Reason:\n{reason}"
                .format(command=command,
                        exit_code=exit_code,
                        reason=stderr))
