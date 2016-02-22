#!/usr/bin/env python
"""
Prints to STDOUT JSON-formatted list of network interfaces which are available
on the system.

USAGE:
    python net_interfaces.py

"""

import json
import netifaces


LOCAL_INTERFACE_NAMES = set(['lo', ])


def is_non_local_interface(name):
    return not any(name.startswith(x) for x in LOCAL_INTERFACE_NAMES)


def get_interface_info_by_name(name):
    addresses = netifaces.ifaddresses(name)
    return {
        'name': name,
        'ipv4': addresses.get(netifaces.AF_INET, []),
        'link': addresses.get(netifaces.AF_LINK, []),
    }


def has_link(info):
    return bool(info.get('link'))


def get_interface_infos():
    names = [
        str(name)
        for name in netifaces.interfaces()
        if is_non_local_interface(name)
    ]
    infos = map(get_interface_info_by_name, names)
    return filter(has_link, infos)


def main():
    infos = get_interface_infos()
    output = json.dumps(infos, sort_keys=True, indent=4)
    print(output)


if __name__ == '__main__':
    main()
