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

from charmhelpers.core.hookenv import action_fail

import contrail_controller_utils as utils


def upgrade_ziu(args):
    utils.signal_ziu("ziu", 0)
    utils.update_ziu("start")
    utils.update_charm_status()


def cancel_ziu(args):
    utils.signal_ziu("ziu", 5)


def apply_defaults(args):
    config['apply-defaults'] = True
    utils.update_charm_status()


ACTIONS = {"upgrade-ziu": upgrade_ziu, "cancel-ziu": cancel_ziu,
           "apply-defaults": apply_defaults}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action {} undefined".format(action_name)
    else:
        try:
            action(args)
        except Exception as e:
            action_fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
