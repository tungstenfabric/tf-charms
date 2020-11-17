#!/usr/bin/env python3

import sys
import json

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    local_unit,
    is_leader,
    leader_get,
    leader_set,
    relation_id,
    relation_get,
    related_units,
    relation_ids,
    status_set,
    relation_set,
    remote_unit,
)

import contrail_analyticsdb_utils as utils
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
    utils.update_charm_status()


@hooks.hook("config-changed")
def config_changed():
    utils.update_nrpe_config()
    if config.changed("control-network"):
        _update_cluster()
        if is_leader() and _address_changed(local_unit(), common_utils.get_ip()):
            _update_analyticsdb()

    docker_utils.config_changed()
    utils.pull_images()
    utils.update_charm_status()

    # leave it as latest - in case of exception in previous steps
    # config.changed doesn't work sometimes (when we saved config in this hook before)
    if config.get("saved-image-tag") != config["image-tag"]:
        utils.update_ziu("image-tag")
        config["saved-image-tag"] = config["image-tag"]
        config.save()


def _update_analyticsdb(rid=None):
    rids = [rid] if rid else relation_ids("contrail-analyticsdb")
    if not rids:
        return

    cluster_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    ip_list = '[]'
    if len(cluster_info) >= config.get("min-cluster-size"):
        ip_list = json.dumps(list(cluster_info.values()))
    settings = {"analyticsdb_ips": ip_list}
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("contrail-analyticsdb-relation-joined")
def analyticsdb_joined():
    _update_analyticsdb(rid=relation_id())


def _value_changed(rel_data, rel_key, cfg_key):
    if rel_key not in rel_data:
        # data is absent in relation. it means that remote charm doesn't
        # send it due to lack of information
        return
    value = rel_data[rel_key]
    if value is not None and value != config.get(cfg_key):
        config[cfg_key] = value
    elif value is None and config.get(cfg_key) is not None:
        config.pop(cfg_key, None)


@hooks.hook("contrail-analyticsdb-relation-changed")
def analyticsdb_changed():
    # this method catches hook from controller and from analytics - so read all
    data = relation_get()
    _value_changed(data, "auth-info", "auth_info")
    _value_changed(data, "orchestrator-info", "orchestrator_info")
    _value_changed(data, "maintenance", "maintenance")
    _value_changed(data, "controller_ips", "controller_ips")
    _value_changed(data, "controller_data_ips", "controller_data_ips")
    _value_changed(data, "analytics_ips", "analytics_ips")
    # TODO: handle changing of all values
    # TODO: set error if orchestrator is changing and container was started
    utils.update_ziu("analyticsdb-changed")
    utils.update_charm_status()


@hooks.hook("contrail-analyticsdb-relation-departed")
def analyticsdb_departed():
    count_controllers = 0
    count_analytics = 0
    for rid in relation_ids("contrail-analyticsdb"):
        for unit in related_units(rid):
            if relation_get("unit-type", unit, rid) == "controller":
                count_controllers += 1
            if relation_get("unit-type", unit, rid) == "analytics":
                count_analytics += 1
    if count_controllers == 0:
        for key in ["auth_info", "orchestrator_info", "controller_ips", "controller_data_ips"]:
            config.pop(key, None)
    if count_analytics == 0:
        config.pop("analytics_ips", None)
    utils.update_charm_status()


def _update_cluster(rid=None):
    rids = [rid] if rid else relation_ids("analyticsdb-cluster")
    if not rids:
        return

    settings = {"unit-address": common_utils.get_ip()}
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("analyticsdb-cluster-relation-joined")
def analyticsdb_cluster_joined():
    _update_cluster(rid=relation_id())


@hooks.hook("analyticsdb-cluster-relation-changed")
def analyticsdb_cluster_changed():
    data = relation_get()
    log("Peer relation changed with {}: {}".format(
        remote_unit(), data))

    ip = data.get("unit-address")
    if not ip:
        log("There is no unit-address in the relation")
    elif is_leader():
        unit = remote_unit()
        if _address_changed(unit, ip):
            _update_analyticsdb()
            utils.update_charm_status()

    utils.update_ziu("cluster-changed")


@hooks.hook("analyticsdb-cluster-relation-departed")
def analyticsdb_cluster_departed():
    if not is_leader():
        return
    unit = remote_unit()
    cluster_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    cluster_info.pop(unit, None)
    log("Unit {} departed. Cluster info: {}".format(unit, str(cluster_info)))
    settings = {"cluster_info": json.dumps(cluster_info)}
    leader_set(settings=settings)

    _update_analyticsdb()
    utils.update_charm_status()


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


@hooks.hook("update-status")
def update_status():
    utils.update_ziu("update-status")
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    _update_cluster()
    saved_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    if is_leader() and not saved_info:
        current_info = utils.get_cluster_info("unit-address", common_utils.get_ip())
        log("Cluster info: {}".format(str(current_info)))
        settings = {"cluster_info": json.dumps(current_info)}
        leader_set(settings=settings)
        _update_analyticsdb()

    utils.update_charm_status()


@hooks.hook('nrpe-external-master-relation-changed')
def nrpe_external_master_relation_changed():
    utils.update_nrpe_config()


@hooks.hook('stop')
def stop():
    utils.stop_analyticsdb()
    utils.remove_created_files()


@hooks.hook("leader-settings-changed")
def leader_settings_changed():
    _update_analyticsdb()
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
        _update_analyticsdb()

    utils.update_charm_status()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
