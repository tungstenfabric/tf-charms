#!/usr/bin/env python3
import base64
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
    action_get,
    action_set,
    log
)

import contrail_command_utils as utils


def _decode_cert(key):
    if not key:
        return None
    try:
        with open('/tmp/juju_ca_cert.pem', 'w') as f:
            f.write(base64.b64decode(key).decode())
        return '/tmp/juju_ca_cert.pem'
    except Exception as e:
        log("Couldn't decode certificate from params['{}']: {}".format(
            key, str(e)), level='ERROR')
    return None


def import_cluster():
    ctx = utils.get_context()
    juju_params = {}
    juju_params["juju_controller"] = action_get("juju-controller")
    juju_params["juju_cacert_path"] = _decode_cert(action_get("juju-ca-cert"))
    juju_params["juju_model_id"] = action_get("juju-model-id")
    juju_params["juju_controller_password"] = action_get("juju-controller-password")
    juju_params["juju_controller_user"] = action_get("juju-controller-user")
    juju_params["juju_cluster_type"] = ctx.get("cloud_orchestrator")

    res, message = utils.import_cluster(juju_params)
    if not res:
        action_fail(message)
    action_set({'result': message})


if __name__ == '__main__':
    import_cluster()
