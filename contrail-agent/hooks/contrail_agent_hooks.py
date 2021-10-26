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
    relation_id,
    related_units,
    status_set,
    unit_private_ip,
    local_unit,
)

import contrail_agent_utils as utils
import common_utils

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

    common_utils.container_engine().install()
    if config["dpdk"]:
        utils.fix_libvirt()
    utils.update_charm_status()


@hooks.hook("config-changed")
def config_changed():
    utils.update_nrpe_config()
    # Charm doesn't support changing of some parameters.
    if config.changed("dpdk"):
        raise Exception("Configuration parameter dpdk couldn't be changed")
    if config.changed("l3mh-cidr"):
        raise Exception("Configuration parameter l3mh-cidr couldn't be changed")
    if config.changed("container_runtime"):
        raise Exception("Configuration parameter container_runtime couldn't be changed")

    if not config["dpdk"]:
        utils.prepare_hugepages_kernel_mode()
    common_utils.container_engine().config_changed()
    utils.pull_images()
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

    maintenance = None
    if "maintenance" in data:
        maintenance = "issu"
    if maintenance:
        config["maintenance"] = maintenance
    else:
        config.pop("maintenance", None)

    info = common_utils.json_loads(data.get("agents-info"), dict())
    k8s_info = info.get("k8s_info")
    if k8s_info:
        ip = unit_private_ip()
        for cluster in k8s_info:
            kubernetes_workers = k8s_info[cluster].get("kubernetes_workers", [])
            if kubernetes_workers and ip in kubernetes_workers:
                config["pod_subnets"] = k8s_info[cluster].get("pod_subnets")
                break

    if "controller_data_ips" in data:
        vhost_ip = utils.get_vhost_ip()
        if vhost_ip:
            settings = {"vhost-address": vhost_ip}
            for rid in relation_ids("agent-cluster"):
                relation_set(relation_id=rid, relation_settings=settings)

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


def _update_tls(rid=None):
    rids = [rid] if rid else relation_ids("tls-certificates")
    if not rids:
        return

    config['tls_present'] = True
    vhost_ip = utils.get_vhost_ip()
    if vhost_ip:
        settings = common_utils.get_tls_settings(vhost_ip)
        for rid in rids:
            relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook('tls-certificates-relation-joined')
def tls_certificates_relation_joined():
    # in cross-model relations we have to provide own name to be sure that we'll find it in response
    relation_set(unit_name=local_unit().replace('/', '_'))
    _update_tls(rid=relation_id())


@hooks.hook('tls-certificates-relation-changed')
def tls_certificates_relation_changed():
    # it can be fired several times without server's cert
    if common_utils.tls_changed(utils.MODULE, relation_get()):
        utils.update_charm_status()


@hooks.hook('tls-certificates-relation-departed')
def tls_certificates_relation_departed():
    config['tls_present'] = False
    common_utils.tls_changed(utils.MODULE, None)
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
    utils.compile_kernel_modules()
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    # call this before calling update_tls to have correct name for certs generation
    utils.fix_dns_settings()
    # to update config flags and certs params if any was changed
    _update_tls()

    utils.update_charm_status()


@hooks.hook('nrpe-external-master-relation-changed')
def nrpe_external_master_relation_changed():
    utils.update_nrpe_config()


@hooks.hook("stop")
def stop():
    utils.stop_agent()
    utils.remove_created_files()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
