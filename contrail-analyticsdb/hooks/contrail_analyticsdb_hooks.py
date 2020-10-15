#!/usr/bin/env python3

import sys
import json

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    is_leader,
    leader_get,
    leader_set,
    relation_get,
    related_units,
    relation_ids,
    status_set,
    relation_set,
    remote_unit,
    ERROR,
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
        settings = {'private-address': common_utils.get_ip()}
        rnames = ("contrail-analyticsdb", "analyticsdb-cluster")
        for rname in rnames:
            for rid in relation_ids(rname):
                relation_set(relation_id=rid, relation_settings=settings)

    docker_utils.config_changed()
    utils.update_charm_status()

    # leave it as latest - in case of exception in previous steps
    # config.changed doesn't work sometimes...
    if config.get("saved-image-tag") != config["image-tag"]:
        utils.update_ziu("image-tag")
        config["saved-image-tag"] = config["image-tag"]
        config.save()


@hooks.hook("contrail-analyticsdb-relation-joined")
def analyticsdb_joined():
    ip_list = leader_get("analyticsdb_ip_list")
    if len(common_utils.json_loads(leader_get("analyticsdb_ip_list"), list())) < config.get("min-cluster-size"):
        ip_list = '[]'

    settings = {'private-address': common_utils.get_ip(),
                "analyticsdb_ips": ip_list}
    relation_set(relation_settings=settings)


def _value_changed(rel_data, rel_key, cfg_key):
    if rel_key not in rel_data:
        # data is absent in relation. it means that remote charm doesn't
        # send it due to lack of information
        return False
    value = rel_data[rel_key]
    if value is not None and value != config.get(cfg_key):
        config[cfg_key] = value
        return True
    elif value is None and config.get(cfg_key) is not None:
        config.pop(cfg_key, None)
        return True
    return False


@hooks.hook("contrail-analyticsdb-relation-changed")
def analyticsdb_changed():
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
    count = 0
    for rid in relation_ids("contrail-analyticsdb"):
        for unit in related_units(rid):
            if relation_get("unit-type", unit, rid) == "controller":
                count += 1
    if count == 0:
        for key in ["auth_info", "orchestrator_info"]:
            config.pop(key, None)
    utils.update_charm_status()


@hooks.hook("analyticsdb-cluster-relation-joined")
def analyticsdb_cluster_joined():
    ip = common_utils.get_ip()
    settings = {"private-address": ip,
                "unit-address": ip}
    relation_set(relation_settings=settings)


@hooks.hook("analyticsdb-cluster-relation-changed")
def analyticsdb_cluster_changed():
    data = relation_get()
    log("Peer relation changed with {}: {}".format(
        remote_unit(), data))

    ip = data.get("unit-address")
    if not ip:
        log("There is no unit-address or data-address in the relation")
        return

    if is_leader():
        unit = remote_unit()
        _address_changed(unit, ip)

    update_relations()
    utils.update_ziu("cluster-changed")
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
    utils.update_charm_status()


@hooks.hook('nrpe-external-master-relation-changed')
def nrpe_external_master_relation_changed():
    utils.update_nrpe_config()


@hooks.hook('stop')
def stop():
    utils.stop_analyticsdb()
    utils.remove_created_files()


def _address_changed(unit, ip):
    ip_list = common_utils.json_loads(leader_get("analyticsdb_ip_list"), list())
    ips = common_utils.json_loads(leader_get("analyticsdb_ips"), dict())
    if ip in ip_list:
        return
    old_ip = ips.get(unit)
    if old_ip:
        index = ip_list.index(old_ip)
        ip_list[index] = ip
        ips[unit] = ip
    else:
        ip_list.append(ip)
        ips[unit] = ip

    log("IP_LIST: {}    IPS: {}".format(str(ip_list), str(ips)))
    settings = {
        "analyticsdb_ip_list": json.dumps(ip_list),
        "analyticsdb_ips": json.dumps(ips)
    }
    leader_set(settings=settings)


def update_relations(rid=None):
    for rid in relation_ids("contrail-analyticsdb"):
        analyticsdb_joined()


@hooks.hook("leader-elected")
def leader_elected():
    ip = common_utils.get_ip()
    var_name = ["ip", "unit-address", ip]
    ip_list = common_utils.json_loads(leader_get("analyticsdb_{}_list".format("ip")), list())
    ips = utils.get_analyticsdb_ips("unit-address", ip)
    if not ip_list:
        ip_list = ips.values()
        log("IP_LIST: {}    IPS: {}".format(str(ip_list), str(ips)))
        settings = {
            "analyticsdb_ip_list": json.dumps(list(ip_list)),
            "analyticsdb_ips": json.dumps(ips)
        }
        leader_set(settings=settings)
    else:
        current_ip_list = ips.values()
        dead_ips = set(ip_list).difference(current_ip_list)
        new_ips = set(current_ip_list).difference(ip_list)
        if new_ips:
            log("There are a new analyticsdbs that are not in the list: " + str(new_ips), level=ERROR)
        if dead_ips:
            log("There are a dead analyticsdbs that are in the list: " + str(dead_ips), level=ERROR)

    update_relations()
    utils.update_charm_status()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
