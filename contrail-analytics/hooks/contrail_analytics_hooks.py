#!/usr/bin/env python3
import sys
import yaml

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
    local_unit,
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
    #open_port(8081, "TCP")


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

    config["config_analytics_ssl_available"] = common_utils.is_config_analytics_ssl_available()
    config.save()

    if config.changed("image-tag"):
        utils.update_ziu("image-tag")

    docker_utils.config_changed()
    utils.update_charm_status()


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
    settings = {"private-address": common_utils.get_ip()}
    relation_set(relation_settings=settings)


@hooks.hook("contrail-analytics-relation-changed")
def contrail_analytics_changed():
    data = relation_get()
    changed = False
    changed |= _value_changed(data, "auth-mode", "auth_mode")
    changed |= _value_changed(data, "auth-info", "auth_info")
    changed |= _value_changed(data, "orchestrator-info", "orchestrator_info")
    changed |= _value_changed(data, "rabbitmq_hosts", "rabbitmq_hosts")
    changed |= _value_changed(data, "maintenance", "maintenance")
    changed |= _value_changed(data, "controller_ips", "controller_ips")
    changed |= _value_changed(data, "controller_data_ips", "controller_data_ips")
    config.save()
    # TODO: handle changing of all values
    # TODO: set error if orchestrator is changing and container was started
    if changed:
        utils.update_charm_status()
        _notify_proxy_services()
    utils.update_ziu("analytics-changed")


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
    settings = {"private-address": common_utils.get_ip(),
                'unit-type': 'analytics'}
    relation_set(relation_settings=settings)


@hooks.hook("contrail-analyticsdb-relation-changed")
def contrail_analyticsdb_changed():
    utils.update_charm_status()
    utils.update_ziu("analyticsdb-changed")


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
    utils.update_ziu("cluster-changed")


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
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    utils.update_charm_status()


def _notify_proxy_services():
    for rid in relation_ids("http-services"):
        if related_units(rid):
            http_services_joined(rid)


def _http_services(vip):
    name = local_unit().replace("/", "-")
    addr = common_utils.get_ip()

    mode = config.get("haproxy-http-mode", "http")
    config_analytics_ssl_available = config.get("config_analytics_ssl_available", False)
    if config_analytics_ssl_available:
        servers = [[name, addr, 8081, "check inter 2000 rise 2 fall 3 ssl verify none"]]
    else:
        servers = [[name, addr, 8081, "check inter 2000 rise 2 fall 3"]]

    result = [{
        "service_name": "contrail-analytics-api",
        "service_host": vip,
        "service_port": 8081,
        "servers": servers }]
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


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
