#!/usr/bin/env python3

import json
import sys

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_get,
    relation_set,
    relation_ids,
    related_units,
    status_set,
)

import contrail_agent_utils as utils
import common_utils
import docker_utils

hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set('maintenance', 'Installing...')

    # TODO: try to remove this call
    common_utils.fix_hostname()

    if not config["dpdk"]:
        utils.prepare_hugepages_kernel_mode()
        if utils.is_reboot_required():
            utils.reboot()

    docker_utils.install()
    if config["dpdk"]:
        utils.fix_libvirt()
    utils.update_charm_status()


@hooks.hook("config-changed")
def config_changed():
    utils.update_nrpe_config()
    # Charm doesn't support changing of some parameters.
    if config.changed("dpdk"):
        raise Exception("Configuration parameter dpdk couldn't be changed")

    if not config["dpdk"]:
        utils.prepare_hugepages_kernel_mode()
    docker_utils.config_changed()
    utils.update_charm_status()

    # leave it as latest - in case of exception in previous steps
    # config.changed doesn't work sometimes...
    if config.get("saved-image-tag") != config["image-tag"]:
        utils.update_ziu("image-tag")
        config["saved-image-tag"] = config["image-tag"]
        config.save()


@hooks.hook("agent-cluster-relation-changed")
def agent_cluster_changed():
    utils.update_charm_status()


@hooks.hook("contrail-controller-relation-joined")
def contrail_controller_joined():
    settings = {'dpdk': config["dpdk"], 'unit-type': 'agent'}
    relation_set(relation_settings=settings)


@hooks.hook("contrail-controller-relation-changed")
def contrail_controller_changed():
    data = relation_get()
    log("RelData: " + str(data))

    def _update_config(key, data_key):
        if data_key in data:
            config[key] = data[data_key]
        else:
            config.pop(key, None)

    _update_config("analytics_servers", "analytics-server")
    _update_config("auth_info", "auth-info")
    _update_config("orchestrator_info", "orchestrator-info")
    _update_config("controller_ips", "controller_ips")
    _update_config("controller_data_ips", "controller_data_ips")
    _update_config("issu_controller_ips", "issu_controller_ips")
    _update_config("issu_controller_data_ips", "issu_controller_data_ips")
    _update_config("issu_analytics_ips", "issu_analytics_ips")

    if "controller_data_ips" in data:
        settings = {"vhost-address": utils.get_vhost_ip()}
        for rid in relation_ids("agent-cluster"):
            relation_set(relation_id=rid, relation_settings=settings)

    maintenance = None
    if "maintenance" in data:
        maintenance = "issu"
    if "ziu" in data or "ziu_done" in data:
        maintenance = "ziu"
    if maintenance:
        config["maintenance"] = maintenance
    else:
        config.pop("maintenance", None)

    config.save()

    utils.update_ziu("controller-changed")
    utils.update_charm_status()


@hooks.hook("contrail-controller-relation-departed")
def contrail_controller_node_departed():
    units = [unit for rid in relation_ids("contrail-controller")
             for unit in related_units(rid)]
    if units:
        return

    # for ISSU case here should not be any removal

    utils.update_charm_status()
    status_set("blocked", "Missing relation to contrail-controller")


@hooks.hook('tls-certificates-relation-joined')
def tls_certificates_relation_joined():
    settings = common_utils.get_tls_settings(utils.get_vhost_ip())
    relation_set(relation_settings=settings)


@hooks.hook('tls-certificates-relation-changed')
def tls_certificates_relation_changed():
    if common_utils.tls_changed(utils.MODULE, relation_get()):
        utils.update_charm_status()


@hooks.hook('tls-certificates-relation-departed')
def tls_certificates_relation_departed():
    if common_utils.tls_changed(utils.MODULE, None):
        utils.update_charm_status()


@hooks.hook("vrouter-plugin-relation-changed")
def vrouter_plugin_changed():
    # accepts 'ready' value in realation (True/False)
    # accepts 'settings' value as a serialized dict to json for contrail-vrouter-agent.conf:
    # {"DEFAULT": {"key1": "value1"}, "SECTION_2": {"key1": "value1"}}
    data = relation_get()
    plugin_ip = data.get("private-address")
    plugin_ready = data.get("ready", False)
    if plugin_ready:
        plugin_ips = common_utils.json_loads(config.get("plugin-ips"), dict())
        plugin_ips[plugin_ip] = common_utils.json_loads(data.get("settings"), dict())
        config["plugin-ips"] = json.dumps(plugin_ips)
        config.save()
    utils.update_charm_status()


@hooks.hook("update-status")
def update_status():
    utils.update_ziu("update-status")
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    utils.update_charm_status()


@hooks.hook('nrpe-external-master-relation-changed')
def nrpe_external_master_relation_changed():
    utils.update_nrpe_config()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
