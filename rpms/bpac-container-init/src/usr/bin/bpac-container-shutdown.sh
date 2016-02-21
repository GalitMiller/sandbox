#!/bin/bash

systemctl stop $( cd /etc/systemd/system/; ls *.service ; cd /usr/lib/systemd/system; ls *.service )

kill -9 1
