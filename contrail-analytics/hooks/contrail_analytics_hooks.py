#!/usr/bin/env python3
import json
import sys
import yaml

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    is_leader,
    leader_get,
    leader_set,
    relation_id,
    relation_get,
    relation_ids,
    related_units,
    status_set,
    relation_set,
    local_unit,
    remote_unit,
    open_port,
    close_port,
)

import contrail_analytics_utils as utils
import common_utils
import docker_utils


hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set("maintenance", "Installing...")

    # TODO: try to remove this call
    common_utils.fix_hostname()

    docker_utils.install()
    utils.update_charm_status()
    # NOTE: do not open port until haproxy can fail
    # https://bugs.launchpad.net/charm-haproxy/+bug/1792939
    # open_port(8081, "TCP")


@hooks.hook("config-changed")
def config_changed():
    utils.update_nrpe_config()
    if config.changed("control-network"):
        _update_cluster()
        if is_leader() and _address_changed(local_unit(), common_utils.get_ip()):
            _update_analytics()
            _update_analyticsdb()

    docker_utils.config_changed()
    utils.update_charm_status()

    _notify_proxy_services()

    # leave it as latest - in case of exception in previous steps
    # config.changed doesn't work sometimes (when we saved config in this hook before)
    if config.get("saved-image-tag") != config["image-tag"]:
        utils.update_ziu("image-tag")
        config["saved-image-tag"] = config["image-tag"]
        config.save()


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


def _update_analytics(rid=None):
    rids = [rid] if rid else relation_ids("contrail-analytics")
    if not rids:
        return

    cluster_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    ip_list = '[]'
    if len(cluster_info) >= config.get("min-cluster-size"):
        ip_list = json.dumps(list(cluster_info.values()))
    settings = {"analytics_ips": ip_list}
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("contrail-analytics-relation-joined")
def contrail_analytics_joined():
    _update_analytics(rid=relation_id())


@hooks.hook("contrail-analytics-relation-changed")
def contrail_analytics_changed():
    data = relation_get()
    _value_changed(data, "auth-mode", "auth_mode")
    _value_changed(data, "auth-info", "auth_info")
    _value_changed(data, "orchestrator-info", "orchestrator_info")
    _value_changed(data, "rabbitmq_hosts", "rabbitmq_hosts")
    _value_changed(data, "maintenance", "maintenance")
    _value_changed(data, "controller_ips", "controller_ips")
    _value_changed(data, "controller_data_ips", "controller_data_ips")
    config.save()
    # TODO: handle changing of all values
    # TODO: set error if orchestrator is changing and container was started
    utils.update_ziu("analytics-changed")
    utils.update_charm_status()
    _notify_proxy_services()


@hooks.hook("contrail-analytics-relation-departed")
def contrail_analytics_departed():
    units = [unit for rid in relation_ids("contrail-analytics")
             for unit in related_units(rid)]
    if not units:
        keys = ["auth_info", "auth_mode", "orchestrator_info", "rabbitmq_hosts",
                "controller_ips", "controller_data_ips"]
        for key in keys:
            config.pop(key, None)
    utils.update_charm_status()
    _notify_proxy_services()


def _update_analyticsdb(rid=None):
    rids = [rid] if rid else relation_ids("contrail-analyticsdb")
    if not rids:
        return

    cluster_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    ip_list = '[]'
    if len(cluster_info) >= config.get("min-cluster-size"):
        ip_list = json.dumps(list(cluster_info.values()))
    settings = {
        "unit-type": "analytics",
        "analytics_ips": ip_list
    }
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("contrail-analyticsdb-relation-joined")
def contrail_analyticsdb_joined():
    _update_analyticsdb(rid=relation_id())


@hooks.hook("contrail-analyticsdb-relation-changed")
def contrail_analyticsdb_changed():
    data = relation_get()
    _value_changed(data, "analyticsdb_ips", "analyticsdb_ips")
    config.save()
    utils.update_ziu("analyticsdb-changed")
    utils.update_charm_status()


@hooks.hook("contrail-analyticsdb-relation-departed")
def contrail_analyticsdb_departed():
    units = [unit for rid in relation_ids("contrail-analyticsdb")
             for unit in related_units(rid)]
    if not units:
        config.pop("analyticsdb_ips", None)
    utils.update_charm_status()


def _update_cluster(rid=None):
    rids = [rid] if rid else relation_ids("analytics-cluster")
    if not rids:
        return

    settings = {"unit-address": common_utils.get_ip()}
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("analytics-cluster-relation-joined")
def analytics_cluster_joined():
    _update_cluster(rid=relation_id())


@hooks.hook("analytics-cluster-relation-changed")
def analytics_cluster_changed():
    data = relation_get()
    log("Peer relation changed with {}: {}".format(
        remote_unit(), data))

    ip = data.get("unit-address")
    if not ip:
        log("There is no unit-address in the relation")
    elif is_leader():
        unit = remote_unit()
        if _address_changed(unit, ip):
            _update_analytics()
            _update_analyticsdb()
            utils.update_charm_status()

    utils.update_ziu("cluster-changed")


@hooks.hook("analytics-cluster-relation-departed")
def analytics_cluster_departed():
    if not is_leader():
        return
    unit = remote_unit()
    cluster_info = common_utils.json_loads(leader_get("cluster_info"), dict())
    cluster_info.pop(unit, None)
    log("Unit {} departed. Cluster info: {}".format(unit, str(cluster_info)))
    settings = {"cluster_info": json.dumps(cluster_info)}
    leader_set(settings=settings)

    _update_analytics()
    _update_analyticsdb()
    utils.update_charm_status()


@hooks.hook('tls-certificates-relation-joined')
def tls_certificates_relation_joined():
    config['tls_present'] = True
    settings = common_utils.get_tls_settings(common_utils.get_ip())
    relation_set(relation_settings=settings)


@hooks.hook('tls-certificates-relation-changed')
def tls_certificates_relation_changed():
    # it can be fired several times without server's cert
    if common_utils.tls_changed(utils.MODULE, relation_get()):
        _notify_proxy_services()
        utils.update_nrpe_config()
        utils.update_charm_status()


@hooks.hook('tls-certificates-relation-departed')
def tls_certificates_relation_departed():
    config['tls_present'] = False
    common_utils.tls_changed(utils.MODULE, None)
    _notify_proxy_services()
    utils.update_nrpe_config()
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
        _update_analytics()
        _update_analyticsdb()

    _notify_proxy_services()
    utils.update_charm_status()


def _http_services(vip):
    name = local_unit().replace("/", "-")
    addr = common_utils.get_ip()

    mode = config.get("haproxy-http-mode", "http")
    ssl_on_backend = config.get("ssl_enabled", False) and common_utils.is_config_analytics_ssl_available()
    if ssl_on_backend:
        servers = [[name, addr, 8081, "check inter 2000 rise 2 fall 3 ssl verify none"]]
    else:
        servers = [[name, addr, 8081, "check inter 2000 rise 2 fall 3"]]

    result = [{
        "service_name": "contrail-analytics-api",
        "service_host": vip,
        "service_port": 8081,
        "servers": servers}]
    if mode == 'http':
        result[0]['service_options'] = [
            "timeout client 3m",
            "option nolinger",
            "timeout server 3m",
            "balance source"]
    else:
        result[0]['service_options'] = [
            "mode http",
            "balance source",
            "hash-type consistent",
            "http-request set-header X-Forwarded-Proto https if { ssl_fc }",
            "http-request set-header X-Forwarded-Proto http if !{ ssl_fc }",
            "option httpchk GET /",
            "option forwardfor",
            "redirect scheme https code 301 if { hdr(host) -i " + str(vip) + " } !{ ssl_fc }",
            "rsprep ^Location:\\ http://(.*) Location:\\ https://\\1"]
        result[0]['crts'] = ["DEFAULT"]

    return result


def _notify_proxy_services(rid=None):
    rids = [rid] if rid else relation_ids("http-services")
    if not rids:
        return

    vip = config.get("vip")
    func = close_port if vip else open_port
    for port in ["8081"]:
        try:
            func(port, "TCP")
        except Exception:
            pass
    data = list() if not vip else _http_services(str(vip))
    settings = {"services": yaml.dump(data)}
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("http-services-relation-joined")
def http_services_joined():
    _notify_proxy_services(rid=relation_id())


@hooks.hook('nrpe-external-master-relation-changed')
def nrpe_external_master_relation_changed():
    utils.update_nrpe_config()


@hooks.hook("stop")
def stop():
    utils.stop_analytics()
    utils.remove_created_files()


@hooks.hook("leader-settings-changed")
def leader_settings_changed():
    _update_analytics()
    _update_analyticsdb()
    utils.update_charm_status()


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
        _update_analytics()
        _update_analyticsdb()

    utils.update_charm_status()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
