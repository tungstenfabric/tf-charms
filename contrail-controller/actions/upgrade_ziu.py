#!/usr/bin/env python3
import os
import sys

_path = os.path.dirname(os.path.realpath(__file__))
_hooks = os.path.abspath(os.path.join(_path, '../hooks'))
_root = os.path.abspath(os.path.join(_path, '..'))

def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)

_add_path(_hooks)
_add_path(_root)

import contrail_controller_utils.py as utils


def upgrade_ziu():
    utils.signal_ziu("ziu", 0)


if __name__ == '__main__':
    upgrade_ziu()
