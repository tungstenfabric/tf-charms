#!/usr/bin/env python3
import sys
import yaml

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    close_port,
    config,
    log,
    open_port,
    relation_id,
    relation_ids,
    relation_get,
    relation_set,
    status_set,
)

import contrail_command_utils as utils
import common_utils


hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set('maintenance', 'Installing...')
    common_utils.container_engine().install()


@hooks.hook("config-changed")
def config_changed():
    # Charm doesn't support changing of some parameters.
    if config.changed("container_runtime"):
        raise Exception("Configuration parameter container_runtime couldn't be changed")
    common_utils.container_engine().config_changed()
    utils.pull_images()
    utils.update_charm_status()
    update_https_relations()


@hooks.hook("update-status")
def update_status():
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    utils.update_charm_status()
    update_https_relations()


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


def update_https_relations(rid=None):
    rids = [rid] if rid else relation_ids("https-services")
    if not rids:
        return

    vip = config.get("vip")
    common_utils.configure_ports(close_port if vip else open_port, ["8079"])

    mode = config.get("haproxy-https-mode", "tcp")
    if mode == "tcp":
        data = yaml.dump(common_utils.https_services_tcp(
            "contrail-command-https", str(vip), 8079))
    elif mode == "http":
        data = yaml.dump(common_utils.https_services_tcp(
            "contrail-command-https", str(vip), 8079))
    for rid in rids:
        relation_set(relation_id=rid, services=data)


@hooks.hook("https-services-relation-joined")
def https_services_joined():
    vip = config.get("vip")
    if not vip:
        raise Exception("VIP must be set for allow relation to haproxy")
    mode = config.get("haproxy-https-mode", "tcp")
    if mode not in ("tcp", "http"):
        raise Exception("Invalid haproxy-https-mode: {}. Possible values: tcp or http".format(mode))
    update_https_relations(rid=relation_id())


@hooks.hook('container-runtime-relation-joined')
@hooks.hook('container-runtime-relation-changed')
def container_runtime_relation_changed():
    data = relation_get()
    if data.get("socket") == '"unix:///var/run/containerd/containerd.sock"':
        config['containerd_present'] = True
    else:
        config['containerd_present'] = False
    utils.update_charm_status()


@hooks.hook('container-runtime-relation-departed')
def container_runtime_relation_departed():
    config['containerd_present'] = False
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
