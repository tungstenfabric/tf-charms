from charmhelpers.core.hookenv import (
    config,
    in_relation_hook,
    local_unit,
    related_units,
    relation_get,
    relation_set,
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
    500: [
        "contrail-node-init",
        "contrail-nodemgr",
        "contrail-external-kafka",
        "contrail-external-cassandra",
        "contrail-external-zookeeper",
    ],
    9999: [
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
    500: {
        "database": [
            "kafka",
            "nodemgr",
            "zookeeper",
            "cassandra"
        ]
    },
    9999: {
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
    ctx = get_context()
    tag = config.get('image-tag')

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

    changed_dict = _render_configs(ctx)
    changed = changed_dict["common"] or changed_dict["analytics-database"]
    docker_utils.compose_run(CONFIGS_PATH + "/docker-compose.yaml", changed)

    common_utils.update_services_status(MODULE, SERVICES.get(ctx["contrail_version"], SERVICES.get(9999)))


def _render_configs(ctx):
    result = dict()

    tfolder = '5.0' if ctx["contrail_version"] == 500 else '5.1'
    result["common"] = common_utils.apply_keystone_ca(MODULE, ctx)
    result["common"] |= common_utils.render_and_log(tfolder + "/analytics-database.env",
        BASE_CONFIGS_PATH + "/common_analyticsdb.env", ctx)
    if ctx["contrail_version"] >= 2002:
        result["common"] |= common_utils.render_and_log(tfolder + "/defaults.env",
            BASE_CONFIGS_PATH + "/defaults_analyticsdb.env", ctx)
    result["analytics-database"] = common_utils.render_and_log(tfolder + "/analytics-database.yaml",
        CONFIGS_PATH + "/docker-compose.yaml", ctx)

    return result


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


# ZUI code block

ziu_relations = [
    "contrail-analyticsdb",
    "analyticsdb-cluster",
]


def config_set(key, value):
    if value is not None:
        config[key] = value
    else:
        config.pop(key, None)
    config.save()


def get_int_from_relation(name, unit=None, rid=None):
    value = relation_get(name, unit, rid)
    return int(value if value else -1)


def signal_ziu(key, value):
    log("ZIU: signal {} = {}".format(key, value))
    config_set(key, value)
    for rname in ziu_relations:
        for rid in relation_ids(rname):
            relation_set(relation_id=rid, relation_settings={key: value})


def sequential_ziu_stage(stage, action):
    prev_ziu_done = stage
    units = [(local_unit(), int(config.get("ziu_done", -1)))]
    for rid in relation_ids("analyticsdb-cluster"):
        for unit in related_units(rid):
            units.append((unit, get_int_from_relation("ziu_done", unit, rid)))
    units.sort(key=lambda x: x[0])
    log("ZIU: sequental stage status {}".format(units))
    for unit in units:
        if unit[0] == local_unit() and prev_ziu_done == stage and unit[1] < stage:
            action(stage)
            return
        prev_ziu_done = unit[1]


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


def ziu_stage_4(ziu_stage, trigger):
    # restart DB
    sequential_ziu_stage(ziu_stage, ziu_restart_db)


def ziu_stage_6(ziu_stage, trigger):
    # finish
    signal_ziu("ziu", None)
    signal_ziu("ziu_done", None)


def ziu_restart_db(stage):
    ctx = get_context()
    _render_configs(ctx)
    docker_utils.compose_run(CONFIGS_PATH + "/docker-compose.yaml")

    result = common_utils.update_services_status(MODULE, SERVICES.get(ctx["contrail_version"], SERVICES.get(9999)))
    if result:
        signal_ziu("ziu_done", stage)


stages = {
    0: ziu_stage_0,
    1: ziu_stage_noop,
    2: ziu_stage_noop,
    3: ziu_stage_noop,
    4: ziu_stage_4,
    5: ziu_stage_noop,
    6: ziu_stage_6,
}
