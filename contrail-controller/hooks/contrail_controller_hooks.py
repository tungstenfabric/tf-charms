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
    relation_set,
    relation_id,
    related_units,
    status_set,
    remote_unit,
    local_unit,
    ERROR,
    open_port,
    close_port,
)

from charmhelpers.core.unitdata import kv

import contrail_controller_utils as utils
import common_utils
import docker_utils

hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set("maintenance", "Installing...")
    config['apply-defaults'] = True
    # TODO: try to remove this call
    common_utils.fix_hostname()

    if config.get('local-rabbitmq-hostname-resolution'):
        utils.update_rabbitmq_cluster_hostnames()

    docker_utils.install()
    utils.update_charm_status()


@hooks.hook("config-changed")
def config_changed():
    utils.update_nrpe_config()
    auth_mode = config.get("auth-mode")
    if auth_mode not in ("rbac", "cloud-admin", "no-auth"):
        raise Exception("Config is invalid. auth-mode must one of: "
                        "rbac, cloud-admin, no-auth.")

    if config.changed("control-network") or config.changed("data-network"):
        ip = common_utils.get_ip()
        data_ip = common_utils.get_ip(config_param="data-network", fallback=ip)

        rel_settings = {"private-address": ip}
        for rname in ("http-services", "https-services"):
            for rid in relation_ids(rname):
                relation_set(relation_id=rid, relation_settings=rel_settings)

        cluster_settings = {"unit-address": ip, "data-address": data_ip}
        if config.get('local-rabbitmq-hostname-resolution'):
            cluster_settings.update({
                "rabbitmq-hostname": utils.get_contrail_rabbit_hostname(),
            })
            # this will also take care of updating the hostname in case
            # control-network changes to something different although
            # such host reconfiguration is unlikely
            utils.update_rabbitmq_cluster_hostnames()
        for rid in relation_ids("controller-cluster"):
            relation_set(relation_id=rid, relation_settings=cluster_settings)

        if is_leader():
            _address_changed(local_unit(), ip, 'ip')
            _address_changed(local_unit(), data_ip, 'data_ip')

    if config.changed("local-rabbitmq-hostname-resolution"):
        if config.get("local-rabbitmq-hostname-resolution"):
            # enabling this option will trigger events on other units
            # so their hostnames will be added as -changed events fire
            # we just need to set our hostname
            utils.update_rabbitmq_cluster_hostnames()
        else:
            kvstore = kv()
            rabbitmq_hosts = kvstore.get(key='rabbitmq_hosts', default={})
            for ip, hostname in rabbitmq_hosts:
                utils.update_hosts_file(ip, hostname, remove_hostname=True)

    config["config_analytics_ssl_available"] = common_utils.is_config_analytics_ssl_available()
    config.save()

    docker_utils.config_changed()
    utils.update_charm_status()

    # leave it after update_charm_status - in case of exception in previous steps
    # config.changed doesn't work sometimes...
    if config.get("saved-image-tag") != config["image-tag"]:
        utils.update_ziu("image-tag")
        config["saved-image-tag"] = config["image-tag"]
        config.save()

    _notify_haproxy_services()
    update_northbound_relations()
    update_southbound_relations()
    update_issu_relations()


@hooks.hook("leader-elected")
def leader_elected():
    for var_name in [("ip", "unit-address", "control-network"),
                     ("data_ip", "data-address", "data-network")]:
        ip_list = common_utils.json_loads(leader_get("controller_{}_list".format(var_name[0])), list())
        ips = utils.get_controller_ips(var_name[1], var_name[2])
        if not ip_list:
            ip_list = ips.values()
            log("{}_LIST: {}    {}S: {}".format(var_name[0].upper(), str(ip_list), var_name[0].upper(), str(ips)))
            settings = {
                "controller_{}_list".format(var_name[0]): json.dumps(list(ip_list)),
                "controller_{}s".format(var_name[0]): json.dumps(ips)
            }
            leader_set(settings=settings)
        else:
            current_ip_list = ips.values()
            dead_ips = set(ip_list).difference(current_ip_list)
            new_ips = set(current_ip_list).difference(ip_list)
            if new_ips:
                log("There are a new controllers that are not in the list: "
                    + str(new_ips), level=ERROR)
            if dead_ips:
                log("There are a dead controllers that are in the list: "
                    + str(dead_ips), level=ERROR)

    update_northbound_relations()
    update_southbound_relations()
    utils.update_charm_status()


@hooks.hook("leader-settings-changed")
def leader_settings_changed():
    utils.update_charm_status()


@hooks.hook("controller-cluster-relation-joined")
def cluster_joined(rel_id=None):
    ip = common_utils.get_ip()
    settings = {
        "unit-address": ip,
        "data-address": common_utils.get_ip(config_param="data-network", fallback=ip)
    }

    if config.get('local-rabbitmq-hostname-resolution'):
        settings["rabbitmq-hostname"] = utils.get_contrail_rabbit_hostname()

    relation_set(relation_id=rel_id, relation_settings=settings)
    utils.update_charm_status()


@hooks.hook("controller-cluster-relation-changed")
def cluster_changed():
    data = relation_get()
    log("Peer relation changed with {}: {}".format(
        remote_unit(), data))

    ip = data.get("unit-address")
    data_ip = data.get("data-address")
    if not ip or not data_ip:
        log("There is no unit-address or data-address in the relation")
        return

    if config.get('local-rabbitmq-hostname-resolution'):
        rabbit_hostname = data.get('rabbitmq-hostname')
        if ip and rabbit_hostname:
            utils.update_hosts_file(ip, rabbit_hostname)

    if is_leader():
        unit = remote_unit()
        _address_changed(unit, ip, 'ip')
        _address_changed(unit, data_ip, 'data_ip')

    update_northbound_relations()
    update_southbound_relations()
    update_issu_relations()
    utils.update_ziu("cluster-changed")
    utils.update_charm_status()


def _address_changed(unit, ip, var_name):
    ip_list = common_utils.json_loads(leader_get("controller_{}_list".format(var_name)), list())
    ips = common_utils.json_loads(leader_get("controller_{}s".format(var_name)), dict())
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
        "controller_{}_list".format(var_name): json.dumps(ip_list),
        "controller_{}s".format(var_name): json.dumps(ips)
    }
    leader_set(settings=settings)


@hooks.hook("controller-cluster-relation-departed")
def cluster_departed():
    if is_leader():
        unit = remote_unit()
        for var_name in ["ip", "data_ip"]:
            ips = common_utils.json_loads(leader_get("controller_{}s".format(var_name)), dict())
            if unit not in ips:
                return
            old_ip = ips.pop(unit)
            ip_list = common_utils.json_loads(leader_get("controller_{}_list".format(var_name)), list())
            ip_list.remove(old_ip)
            log("{}_LIST: {}    {}S: {}".format(var_name.upper(), str(ip_list), var_name.upper(), str(ips)))

            settings = {
                "controller_{}_list".format(var_name): json.dumps(ip_list),
                "controller_{}s".format(var_name): json.dumps(ips)
            }
            leader_set(settings=settings)

    update_northbound_relations()
    update_southbound_relations()
    update_issu_relations()
    utils.update_charm_status()


def update_northbound_relations(rid=None):
    # controller_ips/data_ips are already dumped json
    settings = {
        "unit-type": "controller",
        "maintenance": config.get("maintenance"),
        "auth-mode": config.get("auth-mode"),
        "auth-info": config.get("auth_info"),
        "orchestrator-info": config.get("orchestrator_info"),
        "controller_ips": leader_get("controller_ip_list"),
        "controller_data_ips": leader_get("controller_data_ip_list"),
    }

    if rid:
        relation_set(relation_id=rid, relation_settings=settings)
        return

    for rid in relation_ids("contrail-analytics"):
        relation_set(relation_id=rid, relation_settings=settings)
    for rid in relation_ids("contrail-analyticsdb"):
        relation_set(relation_id=rid, relation_settings=settings)


def update_southbound_relations(rid=None):
    # controller_ips/data_ips are already dumped json
    settings = {
        "maintenance": config.get("maintenance"),
        "analytics-server": json.dumps(utils.get_analytics_list()),
        "auth-mode": config.get("auth-mode"),
        "auth-info": config.get("auth_info"),
        "orchestrator-info": config.get("orchestrator_info"),
        "agents-info": config.get("agents-info"),
        "ssl-enabled": config.get("ssl_enabled") and config.get("config_analytics_ssl_available"),
        # base64 encoded ca-cert
        "ca-cert": config.get("ca_cert"),
        "controller_ips": leader_get("controller_ip_list"),
        "controller_data_ips": leader_get("controller_data_ip_list"),
        "issu_controller_ips": config.get("issu_controller_ips"),
        "issu_controller_data_ips": config.get("issu_controller_data_ips"),
        "issu_analytics_ips": config.get("issu_analytics_ips"),
        "rabbitmq_connection_details": json.dumps(utils.get_rabbitmq_connection_details()),
        "cassandra_connection_details": json.dumps(utils.get_cassandra_connection_details()),
        "zookeeper_connection_details": json.dumps(utils.get_zookeeper_connection_details()),
    }

    for rid in ([rid] if rid else relation_ids("contrail-controller")):
        relation_set(relation_id=rid, relation_settings=settings)


def update_issu_relations(rid=None):
    # controller_ips/data_ips are already dumped json
    settings = {
        "unit-type": "issu",
        "maintenance": config.get("maintenance"),
        "issu_controller_ips": leader_get("controller_ip_list"),
        "issu_controller_data_ips": leader_get("controller_data_ip_list"),
        "issu_analytics_ips": json.dumps(utils.get_analytics_list()),
    }

    for rid in ([rid] if rid else relation_ids("contrail-issu")):
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("contrail-controller-relation-joined")
def contrail_controller_joined(rel_id=None):
    update_southbound_relations(rid=(rel_id if rel_id else relation_id()))


@hooks.hook("contrail-controller-relation-changed")
def contrail_controller_changed():
    data = relation_get()
    if "orchestrator-info" in data:
        config["orchestrator_info"] = data["orchestrator-info"]
    if data.get("unit-type") == 'issu':
        config["maintenance"] = 'issu'
        config["issu_controller_ips"] = data.get("issu_controller_ips")
        config["issu_controller_data_ips"] = data.get("issu_controller_data_ips")
        config["issu_analytics_ips"] = data.get("issu_analytics_ips")
    use_internal_endpoints = data.get("use-internal-endpoints")
    if use_internal_endpoints:
        if not isinstance(use_internal_endpoints, bool):
            use_internal_endpoints = yaml.load(use_internal_endpoints)
            if not isinstance(use_internal_endpoints, bool):
                use_internal_endpoints = False
        config["use_internal_endpoints"] = use_internal_endpoints

    # TODO: set error if orchestrator is changed and container was started
    # with another orchestrator
    if "dpdk" in data:
        # remote unit is an agent
        address = data["private-address"]
        flags = common_utils.json_loads(config.get("agents-info"), dict())
        flags[address] = data["dpdk"]
        config["agents-info"] = json.dumps(flags)
    config.save()

    update_southbound_relations()
    update_northbound_relations()
    utils.update_ziu("controller-changed")
    utils.update_charm_status()


@hooks.hook("contrail-controller-relation-departed")
def contrail_controller_departed():
    # while we have at least one openstack/kubernetes unit on the remote end
    # then we can suggest that orchestrator is still defined
    agents_present = False
    issu_present = False
    for rid in relation_ids("contrail-controller"):
        for unit in related_units(rid):
            utype = relation_get('unit-type', unit, rid)
            if utype == "openstack" or utype == "kubernetes":
                agents_present = True
            if utype == "issu":
                issu_present = True

    changed = False
    if not agents_present and "orchestrator_info" in config:
        config.pop("orchestrator_info", None)
        changed = True
    if not issu_present and config.get("maintenance") == 'issu':
        # TODO: finish ISSU process
        config.pop("maintenance", None)
        config.pop("issu_controller_ips", None)
        config.pop("issu_controller_data_ips", None)
        config.pop("issu_analytics_ips", None)
        changed = True
    if changed:
        update_northbound_relations()
        update_southbound_relations()


@hooks.hook("contrail-analytics-relation-joined")
def analytics_joined(rel_id=None):
    update_northbound_relations(rid=(rel_id if rel_id else relation_id()))
    update_southbound_relations()


@hooks.hook("contrail-analytics-relation-changed")
@hooks.hook("contrail-analytics-relation-departed")
def analytics_changed_departed():
    update_southbound_relations()
    utils.update_ziu("analytics-changed")
    utils.update_charm_status()


@hooks.hook("contrail-analyticsdb-relation-joined")
def analyticsdb_joined(rel_id=None):
    update_northbound_relations(rid=(rel_id if rel_id else relation_id()))


@hooks.hook("contrail-analyticsdb-relation-changed")
def analyticsdb_changed_changed():
    utils.update_ziu("analyticsdb-changed")


@hooks.hook("contrail-auth-relation-changed")
def contrail_auth_changed():
    auth_info = relation_get("auth-info")
    if auth_info is not None:
        config["auth_info"] = auth_info
    else:
        config.pop("auth_info", None)

    update_northbound_relations()
    update_southbound_relations()
    utils.update_charm_status()


@hooks.hook("contrail-auth-relation-departed")
def contrail_auth_departed():
    units = [unit for rid in relation_ids("contrail-auth")
             for unit in related_units(rid)]
    if units:
        return
    config.pop("auth_info", None)

    update_northbound_relations()
    update_southbound_relations()
    utils.update_charm_status()


def _http_services(vip):
    name = local_unit().replace("/", "-")
    addr = common_utils.get_ip()

    mode = config.get("haproxy-http-mode", "http")

    ssl_on_backend = config.get("ssl_enabled", False) and config.get("config_analytics_ssl_available", False)
    if ssl_on_backend:
        servers = [[name, addr, 8082, "check inter 2000 rise 2 fall 3 ssl verify none"]]
    else:
        servers = [[name, addr, 8082, "check inter 2000 rise 2 fall 3"]]

    result = [
        {"service_name": "contrail-api",
         "service_host": vip,
         "service_port": 8082,
         "servers": servers}
    ]
    if mode == 'http':
        result[0]['service_options'] = [
            "timeout client 3m",
            "option nolinger",
            "timeout server 3m",
            "balance source"]
    else:
        result[0]['service_options'] = [
            "timeout client 86400000",
            "mode http",
            "balance source",
            "timeout server 30000",
            "timeout connect 4000",
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
    if not vip:
        raise Exception("VIP must be set for allow relation to haproxy")
    relation_set(relation_id=rel_id,
                 services=yaml.dump(_http_services(str(vip))))


def _https_services_tcp(vip):
    name = local_unit().replace("/", "-")
    addr = common_utils.get_ip()
    return [
        {"service_name": "contrail-webui-https",
         "service_host": vip,
         "service_port": 8143,
         "service_options": [
            "timeout client 86400000",
            "mode tcp",
            "option tcplog",
            "balance source",
            "cookie SERVERID insert indirect nocache",
            "timeout server 30000",
            "timeout connect 4000",
         ],
         "servers": [[name, addr, 8143,
            "cookie " + addr + " weight 1 maxconn 1024 check port 8143"]]},
    ]


def _https_services_http(vip):
    name = local_unit().replace("/", "-")
    addr = common_utils.get_ip()
    return [
        {"service_name": "contrail-webui-https",
         "service_host": vip,
         "service_port": 8143,
         "crts": ["DEFAULT"],
         "service_options": [
            "timeout client 86400000",
            "mode http",
            "balance source",
            "timeout server 30000",
            "timeout connect 4000",
            "hash-type consistent",
            "http-request set-header X-Forwarded-Proto https if { ssl_fc }",
            "http-request set-header X-Forwarded-Proto http if !{ ssl_fc }",
            "option httpchk GET /",
            "option forwardfor",
            "redirect scheme https code 301 if { hdr(host) -i " + str(vip) + " } !{ ssl_fc }",
            "rsprep ^Location:\\ http://(.*) Location:\\ https://\\1",
         ],
         "servers": [[name, addr, 8143,
            "check fall 5 inter 2000 rise 2 ssl verify none"]]},
    ]


@hooks.hook("https-services-relation-joined")
def https_services_joined(rel_id=None):
    vip = config.get("vip")
    if not vip:
        raise Exception("VIP must be set for allow relation to haproxy")
    mode = config.get("haproxy-https-mode", "tcp")
    if mode == "tcp":
        data = _https_services_tcp(str(vip))
    elif mode == "http":
        data = _https_services_http(str(vip))
    else:
        raise Exception("Invalid haproxy-https-mode: {}. Possible values: tcp or http".format(mode))
    relation_set(relation_id=rel_id,
                 services=yaml.dump(data))


def _notify_haproxy_services():
    vip = config.get("vip")
    func = close_port if vip else open_port
    for port in ["8082", "8080", "8143"]:
        try:
            func(port, "TCP")
        except Exception:
            pass
    for rid in relation_ids("http-services"):
        if related_units(rid):
            http_services_joined(rid)
    for rid in relation_ids("https-services"):
        if related_units(rid):
            https_services_joined(rid)


@hooks.hook('tls-certificates-relation-joined')
def tls_certificates_relation_joined():
    settings = common_utils.get_tls_settings(common_utils.get_ip())
    relation_set(relation_settings=settings)


@hooks.hook('tls-certificates-relation-changed')
def tls_certificates_relation_changed():
    if common_utils.tls_changed(utils.MODULE, relation_get()):
        update_southbound_relations()
        utils.update_nrpe_config()
        utils.update_charm_status()


@hooks.hook('tls-certificates-relation-departed')
def tls_certificates_relation_departed():
    if common_utils.tls_changed(utils.MODULE, None):
        update_southbound_relations()
        utils.update_nrpe_config()
        utils.update_charm_status()


@hooks.hook('nrpe-external-master-relation-changed')
def nrpe_external_master_relation_changed():
    utils.update_nrpe_config()


@hooks.hook("contrail-issu-relation-joined")
def contrail_issu_relation_joined(rel_id=None):
    update_issu_relations(rid=(rel_id if rel_id else relation_id()))


@hooks.hook('contrail-issu-relation-changed')
def contrail_issu_relation_changed():
    rel_data = relation_get()
    if "orchestrator-info" in rel_data:
        config["orchestrator_info"] = rel_data["orchestrator-info"]
    else:
        config.pop("orchestrator_info", None)
    config.save()
    update_northbound_relations()
    utils.update_charm_status()

    issu_data = dict()
    for name in ["rabbitmq_connection_details", "cassandra_connection_details", "zookeeper_connection_details"]:
        issu_data.update(common_utils.json_loads(rel_data.get(name), dict()))
    utils.update_issu_state(issu_data)


@hooks.hook("update-status")
def update_status():
    utils.update_ziu("update-status")
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    utils.update_charm_status()
    config_changed()
    for rid in relation_ids("contrail-analytics"):
        if related_units(rid):
            analytics_joined(rel_id=rid)
    for rid in relation_ids("contrail-analyticsdb"):
        if related_units(rid):
            analyticsdb_joined(rel_id=rid)
    for rid in relation_ids("contrail-controller"):
        if related_units(rid):
            contrail_controller_joined(rel_id=rid)
    for rid in relation_ids("contrail-issu"):
        if related_units(rid):
            contrail_issu_relation_joined(rel_id=rid)
    for rid in relation_ids("controller-cluster"):
        if related_units(rid):
            cluster_joined(rel_id=rid)


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
