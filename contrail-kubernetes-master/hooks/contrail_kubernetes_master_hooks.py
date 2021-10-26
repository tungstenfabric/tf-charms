#!/usr/bin/env python3
import json
import sys

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    local_unit,
    log,
    relation_id,
    relation_get,
    relation_ids,
    related_units,
    remote_unit,
    status_set,
    relation_set,
    is_leader,
    leader_get,
    leader_set,
)

import contrail_kubernetes_master_utils as utils
import common_utils


hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set('maintenance', 'Installing...')

    # TODO: try to remove this call
    common_utils.fix_hostname()

    common_utils.container_engine().install()
    status_set("blocked", "Missing relation to contrail-controller")


@hooks.hook("leader-elected")
def leader_elected():
    current_info = utils.get_cluster_info("unit-address", common_utils.get_ip())
    saved_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    log("Cluster current info: {}".format(str(current_info)))
    log("Cluster saved info: {}".format(str(saved_info)))
    if not saved_info:
        log("Cluster info: {}".format(str(current_info)))
        settings = {
            "cluster_info": json.dumps(current_info)
        }
        leader_set(settings=settings)

    _notify_controller()
    utils.update_charm_status()


@hooks.hook("config-changed")
def config_changed():
    # Charm doesn't support changing of some parameters.
    if config.changed("container_runtime"):
        raise Exception("Configuration parameter container_runtime couldn't be changed")
    if config.changed("nested_mode"):
        raise Exception('Nested mode cannot be changed after deployment.')
    # TODO: analyze other params and raise exception if readonly params were changed

    utils.update_nrpe_config()
    if config.changed("control-network"):
        _notify_cluster()
        if is_leader():
            _address_changed(local_unit(), common_utils.get_ip())

    _notify_contrail_kubernetes_node()
    if (config.changed("kubernetes_api_hostname") or
            config.changed("kubernetes_api_secure_port") or
            config.changed("cluster_name") or
            config.changed("pod_subnets")):
        _notify_controller()

    common_utils.container_engine().config_changed()
    utils.pull_images()
    utils.update_charm_status()

    # leave it as latest - in case of exception in previous steps
    # config.changed doesn't work sometimes (when we saved config in this hook before)
    if config.get("saved-image-tag") != config["image-tag"]:
        utils.update_ziu("image-tag")
        config["saved-image-tag"] = config["image-tag"]
        config.save()


def _notify_controller(rid=None):
    rids = [rid] if rid else relation_ids("contrail-controller")
    if not rids:
        return

    settings = {'unit-type': 'kubernetes'}
    settings.update(_get_orchestrator_info())
    settings.update(_get_k8s_info())
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("contrail-controller-relation-joined")
def contrail_controller_joined():
    _notify_controller(rid=relation_id())


@hooks.hook("contrail-controller-relation-changed")
def contrail_controller_changed():
    data = relation_get()

    _update_config(data, "analytics_servers", "analytics-server")
    _update_config(data, "maintenance", "maintenance")
    _update_config(data, "controller_ips", "controller_ips")
    _update_config(data, "controller_data_ips", "controller_data_ips")
    _update_config(data, "auth_info", "auth-info")
    _update_config(data, "orchestrator_info", "orchestrator-info")
    config.save()

    utils.update_ziu("controller-changed")

    utils.update_charm_status()


@hooks.hook("contrail-controller-relation-departed")
def contrail_cotroller_departed():
    units = [unit for rid in relation_ids("contrail-controller")
             for unit in related_units(rid)]
    if units:
        return

    keys = ["auth_info", "orchestrator_info", "controller_ips", "controller_data_ips",
            "analytics-server"]
    for key in keys:
        config.pop(key, None)
    utils.update_charm_status()
    status_set("blocked", "Missing relation to contrail-controller")


def _notify_cluster(rid=None):
    rids = [rid] if rid else relation_ids("kubernetes-master-cluster")
    if not rids:
        return

    settings = {"unit-address": common_utils.get_ip()}
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("kubernetes-master-cluster-relation-joined")
def cluster_joined():
    _notify_cluster(rid=relation_id())


@hooks.hook("kubernetes-master-cluster-relation-changed")
def cluster_changed():
    data = relation_get()
    log("Peer relation changed with {}: {}".format(
        remote_unit(), data))

    ip = data.get("unit-address")
    if not ip:
        log("There is no unit-address in the relation")
    elif is_leader():
        unit = remote_unit()
        _address_changed(unit, ip)
        utils.update_charm_status()

    utils.update_ziu("cluster-changed")


@hooks.hook("kubernetes-master-cluster-relation-departed")
def cluster_departed():
    if not is_leader():
        return
    unit = remote_unit()
    cluster_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    cluster_info.pop(unit, None)
    log("Unit {} departed. Cluster info: {}".format(unit, str(cluster_info)))
    settings = {"cluster_info": json.dumps(cluster_info)}
    leader_set(settings=settings)

    _notify_controller()
    utils.update_charm_status()


def _address_changed(unit, ip):
    cluster_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    if unit in cluster_info and ip == cluster_info[unit]:
        return False
    cluster_info[unit] = ip
    log("Cluster info: {}".format(str(cluster_info)))
    settings = {"cluster_info": json.dumps(cluster_info)}
    leader_set(settings=settings)
    return True


@hooks.hook("kube-api-endpoint-relation-changed")
def kube_api_endpoint_changed():
    data = relation_get()

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


def _notify_contrail_kubernetes_node(rid=None):
    rids = [rid] if rid else relation_ids("contrail-kubernetes-config")
    if not rids:
        return

    data = {}
    data["cluster_name"] = config.get("cluster_name")
    data["pod_subnets"] = config.get("pod_subnets")
    data["nested_mode"] = config.get("nested_mode")
    data["nested_mode_config"] = config.get("nested_mode_config")
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=data)


@hooks.hook("contrail-kubernetes-config-relation-joined")
def contrail_kubernetes_config_joined():
    _notify_contrail_kubernetes_node(rid=relation_id())


@hooks.hook("contrail-kubernetes-config-relation-changed")
@hooks.hook("contrail-kubernetes-config-relation-broken")
@hooks.hook("contrail-kubernetes-config-relation-departed")
def contrail_kubernetes_config_changed(rel_id=None):
    if not is_leader():
        return
    leader_set(settings={"kubernetes_workers": json.dumps(_collect_worker_ips())})
    _notify_controller()


@hooks.hook("leader-settings-changed")
def leader_settings_changed():
    _notify_controller()
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
    utils.update_ziu("update-status")
    utils.update_charm_status()


def _update_config(data, key, data_key):
    if data_key in data:
        changed = config.get(key) != data[data_key]
        config[key] = data[data_key]
    else:
        changed = key in config
        config.pop(key, None)
    return changed


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


def _collect_worker_ips():
    workers_list = []
    for rid in relation_ids("contrail-kubernetes-config"):
        for unit in related_units(rid):
            ip = relation_get("private-address", unit, rid)
            workers_list.append(ip)
    return workers_list


def _get_k8s_info():
    info = {
        "pod_subnets": config.get("pod_subnets"),
        "kubernetes_workers": leader_get("kubernetes_workers"),
        "cluster_name": config.get("cluster_name")
    }
    return {"k8s_info": json.dumps(info)}


def _update_tls(rid=None):
    rids = [rid] if rid else relation_ids("tls-certificates")
    if not rids:
        return

    config['tls_present'] = True
    settings = common_utils.get_tls_settings(common_utils.get_ip())
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


@hooks.hook("upgrade-charm")
def upgrade_charm():
    _notify_contrail_kubernetes_node()
    if is_leader():
        leader_set(settings={"kubernetes_workers": json.dumps(_collect_worker_ips())})
        _notify_controller()

    # to update config flags and certs params if any was changed
    _update_tls()

    utils.update_charm_status()


@hooks.hook('nrpe-external-master-relation-changed')
def nrpe_external_master_relation_changed():
    utils.update_nrpe_config()


@hooks.hook("stop")
def stop():
    utils.stop_kubernetes_master()
    utils.remove_created_files()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
