#!/usr/bin/env python3

import sys
import yaml

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_id,
    relation_get,
    relation_ids,
    status_set,
    relation_set,
)

import contrail_kubernetes_node_utils as utils
import docker_utils


hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set('maintenance', 'Installing...')

    docker_utils.install()
    utils.update_charm_status()


@hooks.hook("config-changed")
def config_changed():
    docker_utils.config_changed()
    utils.update_charm_status()


@hooks.hook("contrail-kubernetes-config-relation-changed")
def contrail_kubernetes_config_changed():
    def _add_to_config(key):
        value = relation_get(key)
        if value:
            config[key] = value

    _add_to_config("cluster_name")
    _add_to_config("pod_subnets")
    _add_to_config("nested_mode_config")
    nested_mode = relation_get("nested_mode")
    if nested_mode is not None:
        if isinstance(nested_mode, str):
            nested_mode = yaml.load(nested_mode)
        config["nested_mode"] = nested_mode
    config.save()
    _notify_kubernetes()
    utils.update_charm_status()


@hooks.hook("cni-relation-joined")
def cni_joined():
    _notify_kubernetes(rid=relation_id())


def _notify_kubernetes(rid=None):
    rids = [rid] if rid else relation_ids("cni")
    if not rids:
        return

    settings = {
        "cidr": config.get("pod_subnets"),
        "cni-conf-file": "/etc/cni/net.d/10-contrail.conf"
    }
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("upgrade-charm")
def upgrade_charm():
    utils.update_charm_status()


@hooks.hook("stop")
def stop():
    utils.stop_kubernetes_node()
    utils.remove_created_files()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
