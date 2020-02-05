from charmhelpers.core.hookenv import (
    config,
    related_units,
    relation_get,
    relation_ids,
    status_set,
    log,
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.core.templating import render
import common_utils
import docker_utils


config = config()


MODULE = "analyticsdb"
BASE_CONFIGS_PATH = "/etc/contrail"

CONFIGS_PATH = BASE_CONFIGS_PATH + "/analytics_database"
IMAGES = {
    '5.0': [
        "contrail-node-init",
        "contrail-nodemgr",
        "contrail-external-kafka",
        "contrail-external-cassandra",
        "contrail-external-zookeeper",
    ],
    '5.1': [
        "contrail-node-init",
        "contrail-nodemgr",
        "contrail-analytics-query-engine",
        "contrail-external-cassandra",
    ],
}
# images for new versions that can be absent in previous releases
IMAGES_OPTIONAL = [
    "contrail-provisioner",
]
SERVICES = {
    '5.0': {
        "database": [
            "kafka",
            "nodemgr",
            "zookeeper",
            "cassandra"
        ]
    },
    '5.1': {
        "database": [
            "query-engine",
            "nodemgr",
            "cassandra",
        ]
    }
}


def servers_ctx():
    analytics_ip_list = []
    for rid in relation_ids("contrail-analyticsdb"):
        for unit in related_units(rid):
            utype = relation_get("unit-type", unit, rid)
            ip = relation_get("private-address", unit, rid)
            if ip and utype == "analytics":
                analytics_ip_list.append(ip)

    return {
        "controller_servers": common_utils.json_loads(config.get("controller_ips"), list()),
        "control_servers": common_utils.json_loads(config.get("controller_data_ips"), list()),
        "analytics_servers": analytics_ip_list}


def analyticsdb_ctx():
    """Get the ipaddres of all analyticsdb nodes"""
    analyticsdb_ip_list = list()
    for rid in relation_ids("analyticsdb-cluster"):
        for unit in related_units(rid):
            ip = relation_get("private-address", unit, rid)
            if ip:
                analyticsdb_ip_list.append(ip)
    # add it's own ip address
    analyticsdb_ip_list.append(common_utils.get_ip())
    return {"analyticsdb_servers": analyticsdb_ip_list}


def get_context():
    ctx = {}
    ctx["module"] = MODULE
    ctx["log_level"] = config.get("log-level", "SYS_NOTICE")
    # previous versions of charm may store next value in config as string.
    ssl_enabled = config.get("ssl_enabled", False)
    if not isinstance(ssl_enabled, bool):
        ssl_enabled = yaml.load(ssl_enabled)
        if not isinstance(ssl_enabled, bool):
            ssl_enabled = False
    ctx["ssl_enabled"] = ssl_enabled
    ctx["analyticsdb_minimum_diskgb"] = config.get("cassandra-minimum-diskgb")
    ctx["jvm_extra_opts"] = config.get("cassandra-jvm-extra-opts")
    ctx["container_registry"] = config.get("docker-registry")
    ctx["contrail_version_tag"] = config.get("image-tag")
    ctx["config_analytics_ssl_available"] = config.get("config_analytics_ssl_available", False)
    ctx["logging"] = docker_utils.render_logging()
    ctx["contrail_version"] = common_utils.get_contrail_version()
    ctx.update(common_utils.json_loads(config.get("orchestrator_info"), dict()))

    ctx.update(servers_ctx())
    ctx.update(analyticsdb_ctx())
    log("CTX: {}".format(ctx))
    ctx.update(common_utils.json_loads(config.get("auth_info"), dict()))
    return ctx


def update_charm_status():
    tag = config.get('image-tag')
    cver = '5.1'
    if '5.0' in tag:
        cver = '5.0'

    for image in IMAGES[cver]:
        try:
            docker_utils.pull(image, tag)
        except Exception as e:
            log("Can't load image {}".format(e))
            status_set('blocked',
                       'Image could not be pulled: {}:{}'.format(image, tag))
            return
    for image in IMAGES_OPTIONAL:
        try:
            docker_utils.pull(image, tag)
        except Exception as e:
            log("Can't load optional image {}".format(e))

    if config.get("maintenance"):
        return

    ctx = get_context()
    missing_relations = []
    if not ctx.get("controller_servers"):
        missing_relations.append("contrail-controller")
    if not ctx.get("analytics_servers"):
        missing_relations.append("contrail-analytics")
    if missing_relations:
        status_set('blocked',
                   'Missing relations: ' + ', '.join(missing_relations))
        return
    if not ctx.get("cloud_orchestrator"):
        status_set('blocked',
                   'Missing cloud_orchestrator info in relation '
                   'with contrail-controller.')
        return
    if ctx.get("cloud_orchestrator") == "openstack" and not ctx.get("keystone_ip"):
        status_set('blocked',
                   'Missing auth info in relation with contrail-controller.')
        return
    # TODO: what should happens if relation departed?

    changed = common_utils.apply_keystone_ca(MODULE, ctx)
    changed |= common_utils.render_and_log(cver + "/analytics-database.env",
        BASE_CONFIGS_PATH + "/common_analyticsdb.env", ctx)
    if ctx["contrail_version"] >= 2002:
        changed |= common_utils.render_and_log(cver + "/defaults.env",
            BASE_CONFIGS_PATH + "/defaults_analyticsdb.env", ctx)
    changed |= common_utils.render_and_log(cver + "/analytics-database.yaml",
        CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(CONFIGS_PATH + "/docker-compose.yaml", changed)

    common_utils.update_services_status(MODULE, SERVICES[cver])


def update_nrpe_config():
    plugins_dir = '/usr/local/lib/nagios/plugins'
    nrpe_compat = nrpe.NRPE()
    common_utils.rsync_nrpe_checks(plugins_dir)
    common_utils.add_nagios_to_sudoers()

    ctl_status_shortname = 'check_contrail_status_' + MODULE
    nrpe_compat.add_check(
        shortname=ctl_status_shortname,
        description='Check contrail-status',
        check_cmd=common_utils.contrail_status_cmd(MODULE, plugins_dir)
    )

    nrpe_compat.write()
