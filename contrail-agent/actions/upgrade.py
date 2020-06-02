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

import contrail_agent_utils as utils


def upgrade():
    utils.stop_agent()
    utils.update_charm_status_for_upgrade()
    utils.update_ziu("upgrade")


if __name__ == '__main__':
    upgrade()
