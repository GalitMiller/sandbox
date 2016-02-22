# -*- coding: utf-8 -*-

import mock
import unittest

from app.config import SENSOR_COMMANDS

from ..helpers import fetch_sensor_interfaces


class HelpersTestCase(unittest.TestCase):

    @mock.patch('app.sensors.helpers.connect_n_exec_sensor_command')
    def test_fetch_sensor_interfaces(self, mock_connect_n_exec_sensor_command):
        sensor = mock.Mock()
        sensor.name = "Mock sensor"
        sensor.hostname = "localhost"
        sensor.ssh_port = 22

        results = fetch_sensor_interfaces(sensor)
        mock_connect_n_exec_sensor_command.assert_called_with(
            sensor,
            SENSOR_COMMANDS.SSH.LIST_INTERFACES.COMMAND,
            SENSOR_COMMANDS.SSH.LIST_INTERFACES.CONN_TIMEOUT,
            SENSOR_COMMANDS.SSH.LIST_INTERFACES.EXEC_TIMEOUT,
        )
        self.assertFalse(results)

        mock_connect_n_exec_sensor_command.return_value = """
        [
            {
                "ipv4": [
                    {
                        "addr": "192.168.1.2",
                        "broadcast": "192.168.1.255",
                        "netmask": "255.255.255.0"
                    }
                ],
                "link": [
                    {
                        "addr": "aa:bb:cc:12:34:56",
                        "broadcast": "ff:ff:ff:ff:ff:ff"
                    }
                ],
                "name": "eth0"
            },
            {
                "ipv4": [
                    {
                        "addr": "192.168.1.3",
                        "broadcast": "192.168.1.255",
                        "netmask": "255.255.255.0"
                    }
                ],
                "link": [
                    {
                        "addr": "dd:ee:ff:78:90:12",
                        "broadcast": "ff:ff:ff:ff:ff:ff"
                    }
                ],
                "name": "wlan1"
            }
        ]
        """

        results = fetch_sensor_interfaces(sensor)
        self.assertEqual(results, {
            'AA:BB:CC:12:34:56': 'eth0',
            'DD:EE:FF:78:90:12': 'wlan1',
        })
