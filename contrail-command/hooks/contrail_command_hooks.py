#!/usr/bin/env python3
import sys

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_get,
    relation_set,
    status_set,
)

import contrail_command_utils as utils
import docker_utils


hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set('maintenance', 'Installing...')
    docker_utils.install()


@hooks.hook("config-changed")
def config_changed():
    docker_utils.config_changed()
    utils.update_charm_status()


@hooks.hook("update-status")
def update_status():
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    utils.update_charm_status()


@hooks.hook("contrail-controller-relation-joined")
def contrail_controller_joined():
    settings = {'unit-type': 'command'}
    relation_set(relation_settings=settings)


@hooks.hook("contrail-controller-relation-changed")
def contrail_controller_changed():

    data = relation_get()
    if "orchestrator-info" in data:
        config["orchestrator_info"] = data["orchestrator-info"]
    else:
        config.pop("orchestrator_info", None)
    config.save()

    utils.update_charm_status()

@hooks.hook("stop")
def stop():
    utils.remove_created_files()

def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
