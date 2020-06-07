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

from charmhelpers.core.hookenv import (
    action_fail,
    config,
)

import contrail_agent_utils as utils
import common_utils


config = config()


def upgrade():
    ctx = utils.get_context()
    if not utils.check_readyness(ctx):
        action_fail("Unit is not ready for upgrade. Please wait for active state.")
        return

    utils.stop_agent()
    changed = utils.render_configs(ctx)
    utils.run_containers(ctx, changed)
    common_utils.update_services_status(utils.MODULE, utils.SERVICES)
    if config.get('maintenance') == 'ziu':
        config["upgraded"] = True
        config.save()

    utils.update_ziu("upgrade")


if __name__ == '__main__':
    upgrade()
