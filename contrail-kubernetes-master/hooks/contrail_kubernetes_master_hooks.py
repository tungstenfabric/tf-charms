#!/usr/bin/env python3
import json
import sys

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_get,
    relation_ids,
    related_units,
    status_set,
    relation_set,
    is_leader,
    leader_get,
)

import contrail_kubernetes_master_utils as utils
import common_utils
import docker_utils


hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set('maintenance', 'Installing...')

    # TODO: try to remove this call
    common_utils.fix_hostname()

    docker_utils.install()
    status_set("blocked", "Missing relation to contrail-controller")


@hooks.hook("leader-elected")
def leader_elected():
    _notify_controller()


@hooks.hook("config-changed")
def config_changed():
    if config.changed("nested_mode"):
        raise Exception('Nested mode cannot be changed after deployment.')
    # TODO: analyze other params and raise exception if readonly params were changed

    utils.update_nrpe_config()
    if config.changed("control-network"):
        settings = {'private-address': common_utils.get_ip()}
        rnames = ("contrail-controller", "contrail-kubernetes-config")
        for rname in rnames:
            for rid in relation_ids(rname):
                relation_set(relation_id=rid, relation_settings=settings)

    _notify_contrail_kubernetes_node()
    if config.changed("kubernetes_api_hostname") or config.changed("kubernetes_api_secure_port"):
        _notify_controller()

    docker_utils.config_changed()
    utils.update_charm_status()


@hooks.hook("contrail-controller-relation-joined")
def contrail_controller_joined(rel_id=None):
    settings = {'unit-type': 'kubernetes'}
    settings.update(_get_orchestrator_info())
    relation_set(relation_id=rel_id, relation_settings=settings)


@hooks.hook("contrail-controller-relation-changed")
def contrail_controller_changed():
    data = relation_get()
    log("RelData: " + str(data))

    _update_config(data, "analytics_servers", "analytics-server")
    _update_config(data, "maintenance", "maintenance")
    _update_config(data, "controller_ips", "controller_ips")
    _update_config(data, "controller_data_ips", "controller_data_ips")
    _update_config(data, "auth_info", "auth-info")
    _update_config(data, "orchestrator_info", "orchestrator-info")
    config.save()

    utils.update_charm_status()


@hooks.hook("contrail-controller-relation-departed")
def contrail_cotroller_departed():
    units = [unit for rid in relation_ids("contrail-controller")
             for unit in related_units(rid)]
    if units:
        return

    utils.update_charm_status()
    status_set("blocked", "Missing relation to contrail-controller")


@hooks.hook("kube-api-endpoint-relation-changed")
def kube_api_endpoint_changed():
    data = relation_get()
    log("RelData: " + str(data))

    changed = _update_config(data, "kubernetes_api_server", "hostname")
    changed |= _update_config(data, "kubernetes_api_port", "port")
    config.save()

    if is_leader():
        changed |= utils.update_kubernetes_token()
    if not changed:
        return

    # notify clients
    _notify_controller()
    # and update self
    utils.update_charm_status()


@hooks.hook("contrail-kubernetes-config-relation-joined")
def contrail_kubernetes_config_joined(rel_id=None):
    data = {}
    data["cluster_name"] = config.get("cluster_name")
    data["pod_subnets"] = config.get("pod_subnets")
    data["nested_mode"] = config.get("nested_mode")
    data["nested_mode_config"] = config.get("nested_mode_config")
    relation_set(relation_id=rel_id, relation_settings=data)


@hooks.hook("leader-settings-changed")
def leader_settings_changed():
    utils.update_charm_status()


@hooks.hook("update-status")
def update_status():
    if is_leader():
        # try to obtain token again if it's not set yet
        changed = utils.update_kubernetes_token()
        if changed:
            # notify clients
            _notify_controller()
    # and update self
    utils.update_charm_status()


def _update_config(data, key, data_key):
    if data_key in data:
        changed = config.get(key) != data[data_key]
        config[key] = data[data_key]
    else:
        changed = key in config
        config.pop(key, None)
    return changed


def _notify_contrail_kubernetes_node():
    for rid in relation_ids("contrail-kubernetes-config"):
        if related_units(rid):
            contrail_kubernetes_config_joined(rel_id=rid)


def _notify_controller():
    for rid in relation_ids("contrail-controller"):
        if related_units(rid):
            contrail_controller_joined(rel_id=rid)


def _get_orchestrator_info():
    info = {"cloud_orchestrator": "kubernetes"}

    def _add_to_info(key, value):
        if value:
            info[key] = value

    _add_to_info("kube_manager_token", leader_get("kube_manager_token"))

    if config.get("kubernetes_api_hostname") and config.get("kubernetes_api_secure_port"):
        _add_to_info("kubernetes_api_server", config.get("kubernetes_api_hostname"))
        _add_to_info("kubernetes_api_secure_port", config.get("kubernetes_api_secure_port"))
    else:
        _add_to_info("kubernetes_api_server", config.get("kubernetes_api_server"))
        _add_to_info("kubernetes_api_secure_port", config.get("kubernetes_api_port"))

    return {"orchestrator-info": json.dumps(info)}


@hooks.hook('tls-certificates-relation-joined')
def tls_certificates_relation_joined():
    settings = common_utils.get_tls_settings(common_utils.get_ip())
    relation_set(relation_settings=settings)


@hooks.hook('tls-certificates-relation-changed')
def tls_certificates_relation_changed():
    if common_utils.tls_changed(utils.MODULE, relation_get()):
        utils.update_charm_status()


@hooks.hook('tls-certificates-relation-departed')
def tls_certificates_relation_departed():
    if common_utils.tls_changed(utils.MODULE, None):
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
