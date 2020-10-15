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
    relation_get,
    relation_ids,
    related_units,
    status_set,
    relation_set,
    local_unit,
    remote_unit,
    open_port,
    close_port,
    ERROR,
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
        settings = {'private-address': common_utils.get_ip()}
        rnames = ("contrail-analytics", "contrail-analyticsdb",
                  "analytics-cluster", "http-services")
        for rname in rnames:
            for rid in relation_ids(rname):
                relation_set(relation_id=rid, relation_settings=settings)

    docker_utils.config_changed()
    utils.update_charm_status()

    _notify_proxy_services()

    # leave it as latest - in case of exception in previous steps
    # config.changed doesn't work sometimes...
    if config.get("saved-image-tag") != config["image-tag"]:
        utils.update_ziu("image-tag")
        config["saved-image-tag"] = config["image-tag"]
        config.save()


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


@hooks.hook("contrail-analytics-relation-joined")
def contrail_analytics_joined():
    ip_list = leader_get("analytics_ip_list")
    if len(common_utils.json_loads(leader_get("analytics_ip_list"), list())) < config.get("min-cluster-size"):
        ip_list = '[]'
    settings = {"private-address": common_utils.get_ip(),
                "analytics_ips": ip_list}
    relation_set(relation_settings=settings)


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
        for key in ["auth_info", "auth_mode", "orchestrator_info", "rabbitmq_hosts"]:
            config.pop(key, None)
    config.save()
    utils.update_charm_status()
    _notify_proxy_services()


@hooks.hook("contrail-analyticsdb-relation-joined")
def contrail_analyticsdb_joined():
    ip_list = leader_get("analytics_ip_list")
    if len(common_utils.json_loads(leader_get("analytics_ip_list"), list())) < config.get("min-cluster-size"):
        ip_list = '[]'

    settings = {"private-address": common_utils.get_ip(),
                'unit-type': 'analytics',
                "analytics_ips": ip_list}
    relation_set(relation_settings=settings)


@hooks.hook("contrail-analyticsdb-relation-changed")
def contrail_analyticsdb_changed():
    utils.update_ziu("analyticsdb-changed")
    utils.update_charm_status()


@hooks.hook("contrail-analyticsdb-relation-departed")
def contrail_analyticsdb_departed():
    utils.update_charm_status()


@hooks.hook("analytics-cluster-relation-joined")
def analytics_cluster_joined():
    settings = {"private-address": common_utils.get_ip()}
    relation_set(relation_settings=settings)
    utils.update_charm_status()


@hooks.hook("analytics-cluster-relation-changed")
def analytics_cluster_changed():
    data = relation_get()
    log("Peer relation changed with {}: {}".format(
        remote_unit(), data))

    ip = data.get("unit-address")
    if not ip:
        log("There is no unit-address or data-address in the relation")
        return

    if config.get('local-rabbitmq-hostname-resolution'):
        rabbit_hostname = data.get('rabbitmq-hostname')
        if ip and rabbit_hostname:
            utils.update_hosts_file(ip, rabbit_hostname)

    if is_leader():
        unit = remote_unit()
        _address_changed(unit, ip, 'ip')

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
        _notify_proxy_services()
        utils.update_nrpe_config()
        utils.update_charm_status()


@hooks.hook('tls-certificates-relation-departed')
def tls_certificates_relation_departed():
    if common_utils.tls_changed(utils.MODULE, None):
        _notify_proxy_services()
        utils.update_nrpe_config()
        utils.update_charm_status()


def _address_changed(unit, ip, var_name):
    ip_list = common_utils.json_loads(leader_get("analytics_{}_list".format(var_name)), list())
    ips = common_utils.json_loads(leader_get("analytics_{}s".format(var_name)), dict())
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

    log("{}_LIST: {}    {}S: {}".format(var_name.upper(), str(ip_list), var_name.upper(), str(ips)))
    settings = {
        "analytics_{}_list".format(var_name): json.dumps(ip_list),
        "analytics_{}s".format(var_name): json.dumps(ips)
    }
    leader_set(settings=settings)


@hooks.hook("update-status")
def update_status():
    utils.update_ziu("update-status")
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    _notify_proxy_services()
    utils.update_charm_status()


def _notify_proxy_services():
    for rid in relation_ids("http-services"):
        if related_units(rid):
            http_services_joined(rid)


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


@hooks.hook("http-services-relation-joined")
def http_services_joined(rel_id=None):
    vip = config.get("vip")
    func = close_port if vip else open_port
    for port in ["8081"]:
        try:
            func(port, "TCP")
        except Exception:
            pass
    data = list() if not vip else _http_services(str(vip))
    relation_set(relation_id=rel_id,
                 services=yaml.dump(data))


@hooks.hook('nrpe-external-master-relation-changed')
def nrpe_external_master_relation_changed():
    utils.update_nrpe_config()


def update_relations(rid=None):
    for rid in relation_ids("contrail-analytics"):
        contrail_analytics_joined()
    for rid in relation_ids("contrail-analyticsdb"):
        contrail_analyticsdb_joined()


@hooks.hook("leader-elected")
def leader_elected():
    ip = common_utils.get_ip()
    var_name = ["ip", "unit-address", ip]
    ip_list = common_utils.json_loads(leader_get("analytics_{}_list".format(var_name[0])), list())
    ips = utils.get_analytics_ips(var_name[1], var_name[2])
    if not ip_list:
        ip_list = ips.values()
        log("{}_LIST: {}    {}S: {}".format(var_name[0].upper(), str(ip_list), var_name[0].upper(), str(ips)))
        settings = {
            "analytics_{}_list".format(var_name[0]): json.dumps(list(ip_list)),
            "analytics_{}s".format(var_name[0]): json.dumps(ips)
        }
        leader_set(settings=settings)
    else:
        current_ip_list = ips.values()
        dead_ips = set(ip_list).difference(current_ip_list)
        new_ips = set(current_ip_list).difference(ip_list)
        if new_ips:
            log("There are a new analytics' that are not in the list: " + str(new_ips), level=ERROR)
        if dead_ips:
            log("There are a dead analytics' that are in the list: " + str(dead_ips), level=ERROR)

    update_relations()
    utils.update_charm_status()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
