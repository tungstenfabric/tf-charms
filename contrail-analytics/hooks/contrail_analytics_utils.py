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


MODULE = "analytics"
BASE_CONFIGS_PATH = "/etc/contrail"

ANALYTICS_CONFIGS_PATH = BASE_CONFIGS_PATH + "/analytics"
ANALYTICS_ALARM_CONFIGS_PATH = BASE_CONFIGS_PATH + "/analytics_alarm"
ANALYTICS_SNMP_CONFIGS_PATH = BASE_CONFIGS_PATH + "/analytics_snmp"
REDIS_CONFIGS_PATH = BASE_CONFIGS_PATH + "/redis"

IMAGES = {
    '5.0': [
        "contrail-node-init",
        "contrail-nodemgr",
        "contrail-analytics-api",
        "contrail-analytics-collector",
        "contrail-analytics-query-engine",
        "contrail-analytics-alarm-gen",
        "contrail-analytics-snmp-collector",
        "contrail-analytics-topology",
        "contrail-external-redis",
    ],
    '5.1': [
        "contrail-node-init",
        "contrail-nodemgr",
        "contrail-analytics-api",
        "contrail-analytics-collector",
        "contrail-analytics-alarm-gen",
        "contrail-analytics-snmp-collector",
        "contrail-analytics-snmp-topology",
        "contrail-external-redis",
    ],
}  
# images for new versions that can be absent in previous releases
IMAGES_OPTIONAL = [
    "contrail-provisioner",
]

SERVICES = {
    '5.0': {
        "analytics": [
            "snmp-collector",
            "query-engine",
            "api",
            "alarm-gen",
            "nodemgr",
            "collector",
            "topology",
        ]
    },
    '5.1': {
        "analytics": [
            "api",
            "nodemgr",
            "collector",
        ],
        "analytics-alarm": [
            "alarm-gen",
            "nodemgr",
            "kafka",
        ],
        "analytics-snmp": [
            "snmp-collector",
            "nodemgr",
            "topology",
        ],
    },
}


def controller_ctx():
    """Get the ipaddress of all contrail control nodes"""
    auth_mode = config.get("auth_mode")
    if auth_mode is None:
        # NOTE: auth_mode must be transmitted by controller
        return {}

    controller_ip_list = common_utils.json_loads(config.get("controller_ips"), list())
    controller_data_ip_list = common_utils.json_loads(config.get("controller_data_ips"), list())
    return {
        "auth_mode": auth_mode,
        "controller_servers": controller_ip_list,
        "control_servers": controller_data_ip_list,
    }


def analytics_ctx():
    """Get the ipaddress of all analytics control nodes"""
    analytics_ip_list = []
    for rid in relation_ids("analytics-cluster"):
        for unit in related_units(rid):
            ip = relation_get("private-address", unit, rid)
            if ip:
                analytics_ip_list.append(ip)
    # add it's own ip address
    analytics_ip_list.append(common_utils.get_ip())
    return {"analytics_servers": analytics_ip_list}


def analyticsdb_ctx():
    """Get the ipaddress of all contrail analyticsdb nodes"""
    analyticsdb_ip_list = []
    for rid in relation_ids("contrail-analyticsdb"):
        for unit in related_units(rid):
            ip = relation_get("private-address", unit, rid)
            if ip:
                analyticsdb_ip_list.append(ip)
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
    ctx["container_registry"] = config.get("docker-registry")
    ctx["contrail_version_tag"] = config.get("image-tag")
    ctx.update(common_utils.json_loads(config.get("orchestrator_info"), dict()))
    ctx["config_analytics_ssl_available"] = config.get("config_analytics_ssl_available", False)
    ctx["logging"] = docker_utils.render_logging()
    ctx["contrail_version"] = common_utils.get_contrail_version()

    ctx.update(controller_ctx())
    ctx.update(analytics_ctx())
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
    if not ctx.get("analyticsdb_servers"):
        missing_relations.append("contrail-analyticsdb")
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
    changed |= common_utils.render_and_log(cver + "/analytics.env",
        BASE_CONFIGS_PATH + "/common_analytics.env", ctx)
    if ctx["contrail_version"] >= 2002:
        changed |= common_utils.render_and_log(cver + "/defaults.env",
            BASE_CONFIGS_PATH + "/defaults_analytics.env", ctx)

    changed |= common_utils.render_and_log(cver + "/analytics.yaml",
        ANALYTICS_CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(ANALYTICS_CONFIGS_PATH + "/docker-compose.yaml", changed)

    if cver == '5.1':
        changed |= common_utils.render_and_log(cver + "/analytics-alarm.yaml",
            ANALYTICS_ALARM_CONFIGS_PATH + "/docker-compose.yaml", ctx)
        docker_utils.compose_run(ANALYTICS_ALARM_CONFIGS_PATH + "/docker-compose.yaml", changed)

        changed |= common_utils.render_and_log(cver + "/analytics-snmp.yaml",
            ANALYTICS_SNMP_CONFIGS_PATH + "/docker-compose.yaml", ctx)
        docker_utils.compose_run(ANALYTICS_SNMP_CONFIGS_PATH + "/docker-compose.yaml", changed)

    # redis is a common service that needs own synchronized env
    changed = common_utils.render_and_log("redis.env",
        BASE_CONFIGS_PATH + "/redis.env", ctx)
    changed |= common_utils.render_and_log("redis.yaml",
        REDIS_CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(REDIS_CONFIGS_PATH + "/docker-compose.yaml", changed)

    common_utils.update_services_status(MODULE, SERVICES[cver])


def update_nrpe_config():
    plugins_dir = '/usr/local/lib/nagios/plugins'
    nrpe_compat = nrpe.NRPE()
    component_ip = common_utils.get_ip()
    common_utils.rsync_nrpe_checks(plugins_dir)
    common_utils.add_nagios_to_sudoers()

    check_api_cmd = 'check_http -H {} -p 8081'.format(component_ip)
    nrpe_compat.add_check(
        shortname='check_analytics_api',
        description='Check Contrail Analytics API',
        check_cmd=check_api_cmd
    )

    ctl_status_shortname = 'check_contrail_status_' + MODULE
    nrpe_compat.add_check(
        shortname=ctl_status_shortname,
        description='Check contrail-status',
        check_cmd=common_utils.contrail_status_cmd(MODULE, plugins_dir)
    )

    nrpe_compat.write()
