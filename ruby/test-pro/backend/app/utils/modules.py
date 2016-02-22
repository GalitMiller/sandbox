# -*- coding: utf-8 -*-

import imp
import os
import sys

from importlib import import_module
from unipath import Path


def autodiscover(module_name, root):
    modules = []

    def _autodiscover(_root):
        try:
            f, filename, description = imp.find_module(module_name, [_root, ])
        except ImportError:
            pass
        else:
            if f:
                f.close()

            import_name = _root.child(module_name).replace(os.sep, '.')
            import_module(import_name)
            modules.append(sys.modules[import_name])

        subdirs = [x for x in _root.listdir() if x.isdir()]
        map(_autodiscover, subdirs)

    _autodiscover(Path(root).name)
    return modules
