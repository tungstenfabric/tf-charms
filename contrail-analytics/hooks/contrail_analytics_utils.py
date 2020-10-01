import yaml

from charmhelpers.core.hookenv import (
    config,
    in_relation_hook,
    related_units,
    relation_get,
    relation_set,
    relation_ids,
    status_set,
    log,
)
from charmhelpers.contrib.charmsupport import nrpe
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
    500: [
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
    9999: [
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
    500: {
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
    9999: {
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
    if not ctx.get("cloud_orchestrators"):
        ctx["cloud_orchestrators"] = list(ctx.get("cloud_orchestrator")) if ctx.get("cloud_orchestrator") else list()

    ctx["config_analytics_ssl_available"] = common_utils.is_config_analytics_ssl_available()
    ctx["logging"] = docker_utils.render_logging()
    ctx["contrail_version"] = common_utils.get_contrail_version()

    ctx.update(controller_ctx())
    ctx.update(analytics_ctx())
    ctx.update(analyticsdb_ctx())
    log("CTX: {}".format(ctx))
    ctx.update(common_utils.json_loads(config.get("auth_info"), dict()))
    return ctx


def update_charm_status():
    ctx = get_context()
    tag = config.get('image-tag')
###EDIT###
    if not ctx.get("analyticsdb_servers"):
        for key in IMAGES:
            key_list = IMAGES.get(key)
            for list_var in key_list
                if list_var == "contrail-analytics-topology":
                    key_list.remove("contrail-analytics-topology")
                if list_var == "contrail-analytics-alarm-gen":
                    key_list.remove("contrail-analytics-alarm-gen")
            IMAGES.update({key: key_list})
        for key in SERVICES:
            key_dict = SERVICES.get(key)
            for key_ in key_dict.keys():
                key_list = key_dict.get(key_)
                for list_var in key_list:
                    if list_var == "topology":
                        key_list.remove("topology")
                    if list_var == "alarm-gen":
                        key_list.remove("alarm-gen")
                key_dict.update({key_: key_list})
            SERVICES.update({key: key_dict})

    images = IMAGES.get(ctx["contrail_version"], IMAGES.get(9999))
    for image in images:
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
        log("ISSU Maintenance is in progress")
        status_set('maintenance', 'issu is in progress')
        return
    if int(config.get("ziu", -1)) > -1:
        log("ZIU Maintenance is in progress")
        status_set('maintenance',
                   'ziu is in progress - stage/done = {}/{}'.format(config.get("ziu"), config.get("ziu_done")))
        return

    _update_charm_status(ctx)


def _update_charm_status(ctx):
    missing_relations = []
    if not ctx.get("controller_servers"):
        missing_relations.append("contrail-controller")
    ###EDIT###
    #if not ctx.get("analyticsdb_servers"):
    #    missing_relations.append("contrail-analyticsdb")
    if missing_relations:
        status_set('blocked',
                   'Missing relations: ' + ', '.join(missing_relations))
        return
    if len(ctx.get("analytics_servers")) < config.get("min-cluster-size"):
        status_set('blocked',
                   'Count of cluster nodes is not enough ({} < {}).'.format(
                       len(ctx.get("analytics_servers")), config.get("min-cluster-size")
                   ))
        return
    if not ctx.get("cloud_orchestrator"):
        status_set('blocked',
                   'Missing cloud_orchestrator info in relation '
                   'with contrail-controller.')
        return
    if "openstack" in ctx.get("cloud_orchestrators") and not ctx.get("keystone_ip"):
        status_set('blocked',
                   'Missing auth info in relation with contrail-controller.')
        return
    # TODO: what should happens if relation departed?

    changed_dict = _render_configs(ctx)
    changed = changed_dict["common"]

    service_changed = changed_dict["analytics"]
    docker_utils.compose_run(ANALYTICS_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

    ###EDIT###
    if ctx["contrail_version"] >= 510 and ctx.get("analyticsdb_servers"):
        service_changed = changed_dict["analytics-alarm"]
        docker_utils.compose_run(ANALYTICS_ALARM_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

        service_changed = changed_dict["analytics-snmp"]
        docker_utils.compose_run(ANALYTICS_SNMP_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

    # redis is a common service that needs own synchronized env
    service_changed = changed_dict["redis"]
    docker_utils.compose_run(REDIS_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

    common_utils.update_services_status(MODULE, SERVICES.get(ctx["contrail_version"], SERVICES.get(9999)))


def _render_configs(ctx):
    result = dict()

    tfolder = '5.0' if ctx["contrail_version"] == 500 else '5.1'
    result["common"] = common_utils.apply_keystone_ca(MODULE, ctx)
    result["common"] |= common_utils.render_and_log(
        tfolder + "/analytics.env",
        BASE_CONFIGS_PATH + "/common_analytics.env", ctx)

    result["analytics"] = common_utils.render_and_log(
        tfolder + "/analytics.yaml",
        ANALYTICS_CONFIGS_PATH + "/docker-compose.yaml", ctx)

    ###EDIT###
    if ctx["contrail_version"] >= 510 and ctx.get("analyticsdb_servers"):
        result["analytics-alarm"] = common_utils.render_and_log(
            tfolder + "/analytics-alarm.yaml",
            ANALYTICS_ALARM_CONFIGS_PATH + "/docker-compose.yaml", ctx)

        result["analytics-snmp"] = common_utils.render_and_log(
            tfolder + "/analytics-snmp.yaml",
            ANALYTICS_SNMP_CONFIGS_PATH + "/docker-compose.yaml", ctx)
    # TODO:  think about removing analytics-alarm.yaml and analytics-snmp.yaml
    # redis is a common service that needs own synchronized env
    result["redis"] = common_utils.render_and_log(
        "redis.env",
        BASE_CONFIGS_PATH + "/redis.env", ctx)
    result["redis"] |= common_utils.render_and_log(
        "redis.yaml",
        REDIS_CONFIGS_PATH + "/docker-compose.yaml", ctx)

    return result


def update_nrpe_config():
    plugins_dir = '/usr/local/lib/nagios/plugins'
    nrpe_compat = nrpe.NRPE()
    component_ip = common_utils.get_ip()
    common_utils.rsync_nrpe_checks(plugins_dir)
    common_utils.add_nagios_to_sudoers()

    ssl_on_backend = config.get("ssl_enabled", False) and common_utils.is_config_analytics_ssl_available()
    if ssl_on_backend:
        check_api_cmd = 'check_http -S -H {} -p 8081'.format(component_ip)
    else:
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


# ZUI code block

ziu_relations = [
    "contrail-analytics",
    "contrail-analyticsdb",
    "analytics-cluster",
]


def config_set(key, value):
    if value is not None:
        config[key] = value
    else:
        config.pop(key, None)
    config.save()


def signal_ziu(key, value):
    log("ZIU: signal {} = {}".format(key, value))
    for rname in ziu_relations:
        for rid in relation_ids(rname):
            relation_set(relation_id=rid, relation_settings={key: value})
    config_set(key, value)


def update_ziu(trigger):
    if in_relation_hook():
        ziu_stage = relation_get("ziu")
        log("ZIU: stage from relation {}".format(ziu_stage))
    else:
        ziu_stage = config.get("ziu")
        log("ZIU: stage from config {}".format(ziu_stage))
    if ziu_stage is None:
        return
    ziu_stage = int(ziu_stage)
    config_set("ziu", ziu_stage)
    if ziu_stage > int(config.get("ziu_done", -1)):
        log("ZIU: run stage {}, trigger {}".format(ziu_stage, trigger))
        stages[ziu_stage](ziu_stage, trigger)


def ziu_stage_noop(ziu_stage, trigger):
    signal_ziu("ziu_done", ziu_stage)


def ziu_stage_0(ziu_stage, trigger):
    # update images
    if trigger == "image-tag":
        signal_ziu("ziu_done", ziu_stage)


def ziu_stage_1(ziu_stage, trigger):
    # stop API services
    cver = common_utils.get_contrail_version()
    docker_utils.compose_down(ANALYTICS_CONFIGS_PATH + "/docker-compose.yaml")
    docker_utils.compose_down(REDIS_CONFIGS_PATH + "/docker-compose.yaml")
    ###EDIT###
    if cver >= 510 and ctx.get("analyticsdb_servers"):
        docker_utils.compose_down(ANALYTICS_ALARM_CONFIGS_PATH + "/docker-compose.yaml")
        docker_utils.compose_down(ANALYTICS_SNMP_CONFIGS_PATH + "/docker-compose.yaml")

    signal_ziu("ziu_done", ziu_stage)


def ziu_stage_2(ziu_stage, trigger):
    # start API services
    ctx = get_context()
    _render_configs(ctx)
    docker_utils.compose_run(ANALYTICS_CONFIGS_PATH + "/docker-compose.yaml")
    docker_utils.compose_run(REDIS_CONFIGS_PATH + "/docker-compose.yaml")
    ###EDIT###
    if ctx["contrail_version"] >= 510 and ctx.get("analyticsdb_servers"):
        docker_utils.compose_run(ANALYTICS_ALARM_CONFIGS_PATH + "/docker-compose.yaml")
        docker_utils.compose_run(ANALYTICS_SNMP_CONFIGS_PATH + "/docker-compose.yaml")

    result = common_utils.update_services_status(MODULE, SERVICES.get(ctx["contrail_version"], SERVICES.get(9999)))
    if result:
        signal_ziu("ziu_done", ziu_stage)


def ziu_stage_6(ziu_stage, trigger):
    # finish
    signal_ziu("ziu", None)
    signal_ziu("ziu_done", None)


stages = {
    0: ziu_stage_0,
    1: ziu_stage_1,
    2: ziu_stage_2,
    3: ziu_stage_noop,
    4: ziu_stage_noop,
    5: ziu_stage_noop,
    6: ziu_stage_6,
}
