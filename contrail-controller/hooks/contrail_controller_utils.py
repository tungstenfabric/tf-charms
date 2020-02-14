import os
import tempfile
import socket

from charmhelpers.core.hookenv import (
    config,
    related_units,
    relation_ids,
    relation_get,
    status_set,
    leader_get,
    log,
    INFO,
    local_unit,
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.core.templating import render
from charmhelpers.core.unitdata import kv
import common_utils
import docker_utils

config = config()

MODULE = "controller"

BASE_CONFIGS_PATH = "/etc/contrail"

CONFIG_API_CONFIGS_PATH = BASE_CONFIGS_PATH + "/config_api"
CONFIG_DATABASE_CONFIGS_PATH = BASE_CONFIGS_PATH + "/config_database"
CONTROL_CONFIGS_PATH = BASE_CONFIGS_PATH + "/control"
WEBUI_CONFIGS_PATH = BASE_CONFIGS_PATH + "/webui"
REDIS_CONFIGS_PATH = BASE_CONFIGS_PATH + "/redis"

IMAGES = [
    "contrail-node-init",
    "contrail-nodemgr",
    "contrail-controller-config-api",
    "contrail-controller-config-svcmonitor",
    "contrail-controller-config-schema",
    "contrail-controller-config-devicemgr",
    "contrail-controller-control-control",
    "contrail-controller-control-named",
    "contrail-controller-control-dns",
    "contrail-controller-webui-web",
    "contrail-controller-webui-job",
    "contrail-external-cassandra",
    "contrail-external-zookeeper",
    "contrail-external-rabbitmq",
    "contrail-external-redis",
]
# images for new versions that can be absent in previous releases
IMAGES_OPTIONAL = [
    "contrail-provisioner",
    "contrail-controller-config-dnsmasq",
]

SERVICES = {
    "control": [
        "control",
        "nodemgr",
        "named",
        "dns",
    ],
    "config-database": [
        "nodemgr",
        "zookeeper",
        "rabbitmq",
        "cassandra",
    ],
    "webui": [
        "web",
        "job",
    ],
    "config": [
        "svc-monitor",
        "nodemgr",
        "device-manager",
        "api",
        "schema",
    ],
}


def get_controller_ips(address_type, config_param):
    controller_ips = dict()
    for rid in relation_ids("controller-cluster"):
        for unit in related_units(rid):
            ip = relation_get(address_type, unit, rid)
            controller_ips[unit] = ip
    # add it's own ip address
    controller_ips[local_unit()] = common_utils.get_ip(config_param=config_param)
    return controller_ips


def get_analytics_list():
    analytics_ip_list = []
    for rid in relation_ids("contrail-analytics"):
        for unit in related_units(rid):
            ip = relation_get("private-address", unit, rid)
            if ip:
                analytics_ip_list.append(ip)
    return analytics_ip_list


def get_context():
    ctx = {}
    ctx["module"] = MODULE
    ctx["log_level"] = config.get("log-level", "SYS_NOTICE")
    ctx["bgp_asn"] = config.get("bgp-asn", "64512")
    ctx["flow_export_rate"] = config.get("flow-export-rate")
    ctx["auth_mode"] = config.get("auth-mode")
    ctx["cloud_admin_role"] = config.get("cloud-admin-role")
    ctx["global_read_only_role"] = config.get("global-read-only-role")
    ctx["configdb_minimum_diskgb"] = config.get("cassandra-minimum-diskgb")
    ctx["jvm_extra_opts"] = config.get("cassandra-jvm-extra-opts")
    ctx["container_registry"] = config.get("docker-registry")
    ctx["contrail_version_tag"] = config.get("image-tag")
    ctx["contrail_version"] = common_utils.get_contrail_version()
    ctx.update(common_utils.json_loads(config.get("orchestrator_info"), dict()))

    ctx["ssl_enabled"] = config.get("ssl_enabled", False)
    ctx["config_analytics_ssl_available"] = config.get("config_analytics_ssl_available", False)
    ctx["logging"] = docker_utils.render_logging()

    ips = common_utils.json_loads(leader_get("controller_ip_list"), list())
    data_ips = common_utils.json_loads(leader_get("controller_data_ip_list"), list())
    ctx["controller_servers"] = ips
    ctx["control_servers"] = data_ips
    ctx["analytics_servers"] = get_analytics_list()
    log("CTX: " + str(ctx))
    ctx.update(common_utils.json_loads(config.get("auth_info"), dict()))
    return ctx


def update_charm_status():
    tag = config.get('image-tag')
    for image in IMAGES:
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
    if not ctx.get("analytics_servers"):
        missing_relations.append("contrail-analytics")
    if common_utils.get_ip() not in ctx.get("controller_servers"):
        missing_relations.append("contrail-cluster")
    if missing_relations:
        status_set('blocked',
                   'Missing relations: ' + ', '.join(missing_relations))
        return
    if not ctx.get("cloud_orchestrator"):
        status_set('blocked',
                   'Missing cloud orchestrator info in relations.')
        return
    if ctx.get("cloud_orchestrator") == "openstack" and not ctx.get("keystone_ip"):
        status_set('blocked',
                   'Missing auth info in relation with contrail-auth.')
        return
    # TODO: what should happens if relation departed?

    changed = common_utils.apply_keystone_ca(MODULE, ctx)
    changed |= common_utils.render_and_log("config.env",
        BASE_CONFIGS_PATH + "/common_config.env", ctx)
    if ctx["contrail_version"] >= 2002:
        changed |= common_utils.render_and_log("defaults.env",
            BASE_CONFIGS_PATH + "/defaults_controller.env", ctx)

    service_changed = common_utils.render_and_log("config-api.yaml",
        CONFIG_API_CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(CONFIG_API_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

    service_changed = common_utils.render_and_log("config-database.yaml",
        CONFIG_DATABASE_CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(CONFIG_DATABASE_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

    service_changed = common_utils.render_and_log("control.yaml",
        CONTROL_CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(CONTROL_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

    service_changed = common_utils.render_and_log("webui.yaml",
        WEBUI_CONFIGS_PATH + "/docker-compose.yaml", ctx)
    service_changed |= common_utils.render_and_log("web.env",
        BASE_CONFIGS_PATH + "/common_web.env", ctx)
    docker_utils.compose_run(WEBUI_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

    # redis is a common service that needs own synchronized env
    service_changed = common_utils.render_and_log("redis.env",
        BASE_CONFIGS_PATH + "/redis.env", ctx)
    service_changed |= common_utils.render_and_log("redis.yaml",
        REDIS_CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(REDIS_CONFIGS_PATH + "/docker-compose.yaml", changed or service_changed)

    common_utils.update_services_status(MODULE, SERVICES)


def update_hosts_file(ip, hostname, remove_hostname=False):
    """Update /etc/hosts and template files with cluster names and IPs.

    RabbitMQ requires NODE names in a cluster to be resolvable.
    https://www.rabbitmq.com/clustering.html#issues-hostname

    In a multi-homed host scenario cluster IPs may have FQDNs structured
    as interface_name.host_name.domain which will result in an issue if
    a short name is derived from an FQDN by taking its first part.
    See https://github.com/Juniper/contrail-charms/issues/50

    This function updates /etc/hosts file with resolutions for IP -> hostname
    lookups. Also it updates template /etc/cloud/templates/hosts.debian.tmpl
    """
    _update_hosts_file("/etc/hosts", ip, hostname, remove_hostname=remove_hostname)
    _update_hosts_file("/etc/cloud/templates/hosts.debian.tmpl", ip, hostname, remove_hostname=remove_hostname)

    kvstore = kv()
    rabbitmq_hosts = kvstore.get(key='rabbitmq_hosts', default={})
    if remove_hostname:
        rabbitmq_hosts.pop(ip)
    else:
        # finally, update the unitdata with the notion of new hosts values
        # managed
        rabbitmq_hosts.update({ip: hostname})
    kvstore.set(key='rabbitmq_hosts', value=rabbitmq_hosts)
    # flush the store to persist data to sqlite
    kvstore.flush()


def _update_hosts_file(file, ip, hostname, remove_hostname=False):
    with open(file, 'r') as hosts:
        lines = hosts.readlines()

    log("Updating file {} with: {}:{}, remove={} (current: {})".format(
        file, ip, hostname, remove_hostname, lines),
        level=INFO)

    newlines = []
    hostname_present = False
    for line in lines:
        _line = line.split()
        if len(_line) < 2:
            newlines.append(line)
            continue

        parsed_ip = _line[0]
        parsed_hostname = _line[1]
        aliases = _line[2:]

        # handle a single hostname or alias removal
        if remove_hostname and parsed_ip == ip:
            log("Removing ip:hostname pair: {}:{}".format(ip, hostname))
            aliases = [a for a in aliases if a != hostname]
            if parsed_hostname != hostname or not aliases:
                continue
            newlines.append(' '.join([ip, ' '.join(aliases)]))

        hostname_mismatch = (ip == parsed_ip and hostname != parsed_hostname)
        log("hostname mismatch: {}".format(hostname_mismatch))
        if hostname_mismatch and hostname_present:
            # malformed /etc/hosts - let's let an operator sort this out
            # and retry hook execution if needed
            raise Exception('Multiple lines with ip {} '
                            'encountered'.format(ip))

        if hostname_mismatch and not hostname_present:
            log("Changing an existing entry for {}".format(
                hostname))
            # move the hostname that is already present to aliases and use
            # the one provided by the caller instead
            aliases.append(parsed_hostname)
            aliases = [a for a in aliases if a != hostname]
            newlines.append(' '.join([ip, hostname, ' '.join(aliases)]))
            # set a flag saying that we already encountered that hostname
            hostname_present = True
        elif not hostname_mismatch and not hostname_present:
            log("No hostname mismatches and have not seen {}"
                " in any previous lines".format(hostname))

            if not hostname == parsed_hostname:
                newlines.append("%s %s\n" % (ip, hostname))

            # it's not a mismatch so we need to mark it the hostname as present
            hostname_present = True

            # also need to preserve an old line
            newlines.append(line)
        elif ip != parsed_ip:
            log("Preserving the line as an IP is different: {}".format(line))
            # no mismatches - just keep the line
            newlines.append(line)

    # if we haven't updated any existing lines for this hostname, just add it
    if not hostname_present:
        log("Adding a new entry for {}:{}".format(ip, hostname))
        newlines.append("%s %s\n" % (ip, hostname))

    log("New hosts file contents: {}".format(newlines))

    # create a temporary file in the same directory to ensure that moving
    # it over /etc/hosts is atomic (not done across file systems)
    tdir = os.path.dirname(file)
    with tempfile.NamedTemporaryFile(dir=tdir, delete=False) as tmpfile:
        with open(tmpfile.name, 'w') as hosts:
            for line in newlines:
                hosts.write(line)

    # atomically replace the target file so that application runtimes do not
    # see intermediate changes to the file
    log("moving {} over {}".format(tmpfile.name, file))
    os.rename(tmpfile.name, file)
    os.chmod(file, 0o644)


def get_contrail_rabbit_hostname():
    """Return this unit's hostname.

    @returns hostname
    """
    # /proc/sys/kernel/hostname may contain an FQDN so try to split
    # and take a short name
    return '{}-contrail-rmq'.format(socket.gethostname().split('.')[0])


def update_rabbitmq_cluster_hostnames():
    """Updates /etc/hosts with rabbitmq cluster node hostnames"""
    ip = common_utils.get_ip()
    update_hosts_file(ip, get_contrail_rabbit_hostname())


def get_cassandra_connection_details():
    return {
        "cassandra_address_list": common_utils.json_loads(leader_get("controller_ip_list"), list()),
    }


def get_zookeeper_connection_details():
    return {
        "zookeeper_address_list": common_utils.json_loads(leader_get("controller_ip_list"), list()),
    }


def get_rabbitmq_connection_details():
    return {
        "rabbit_q_name": "vnc-config.issu-queue",
        "rabbit_vhost": "/",
        "rabbit_port": "5673",
        "rabbit_address_list": common_utils.json_loads(leader_get("controller_ip_list"), list()),
    }


def update_issu_state(issu_relation_data):
    ctx = {'old': issu_relation_data}
    ctx["new"] = get_cassandra_connection_details()
    ctx["new"].update(get_rabbitmq_connection_details())
    ctx["new"].update(get_zookeeper_connection_details())

    common_utils.render_and_log("contrail-issu.conf", BASE_CONFIGS_PATH + "/contrail-issu.conf", ctx)
    # TODO run docker


def update_nrpe_config():
    plugins_dir = '/usr/local/lib/nagios/plugins'
    nrpe_compat = nrpe.NRPE()
    component_ip = common_utils.get_ip()
    common_utils.rsync_nrpe_checks(plugins_dir)
    common_utils.add_nagios_to_sudoers()

    check_ui_cmd = 'check_http -H {} -p 8143 -S'.format(component_ip)
    nrpe_compat.add_check(
        shortname='check_contrail_web_ui',
        description='Check Contrail WebUI',
        check_cmd=check_ui_cmd
    )

    check_api_cmd = 'check_http -H {} -p 8082'.format(component_ip)
    nrpe_compat.add_check(
        shortname='check_contrail_api',
        description='Check Contrail API',
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

stages = { 
    0: ziu_stage_0,
    1: ziu_stage_1,
    2: ziu_stage_2,
    3: ziu_stage_3,
    4: ziu_stage_4
}

ziu_relations = (
    "contrail-analytics",
    "contrail-analyticsdb",
    "controller-cluster",
    "contrail-controller"
)


def config_set(key, value):
    config[key] = value
    config.save()


def signal_ziu(key, value):
    config_set(key, value)
    for rname in ziu_relations:
        for rid in relation_ids(rname):
            relation_set(relation_id=rid, relation_settings={key: value})


def check_ziu_stage_done(stage)
    for rname in ziu_relations:
        for rid in relation_ids(rname):
            for unit in related_units(rid):
                if relation_get("ziu_done", unit, rid) != stage):
                    return False
    return True


def sequential_ziu_stage(stage, action)
    prev_ziu_done = stage
    # TODO: probably some of the lists here should be first sorted to scan through them (in case juju mix them up)
    for rid in relation_ids("controller-cluster"):
        for unit in related_units(rid):
            ziu_done = relation_get("ziu_done", unit, rid):
            if unit == local_unit() and prev_ziu_done and prev_ziu_done = stage and ziu_done and ziu_done < ziu_stage:
                action()
                signal_ziu("ziu_done")
                return
            prev_ziu_done = ziu_done


def update_ziu(trigger):
    ziu_stage = relation_get("ziu"):
    if ziu_stage:
        config_set("ziu", ziu_stage)
        log("ZIU: run stage {}, trigger {}".format(ziu_stage, trigger))
        stages[ziu_stage](ziu_stage, trigger)
        # This code is on controller only
        if is_leader()
            check_ziu_stage_done(ziu_stage):
                signal_ziu("ziu", ziu_stage+1)


def ziu_stage_0(ziu_stage, trigger):
    if trigger == "image-tag":
        signal_ziu("ziu_done": ziu_stage)


def ziu_stage_1(ziu_stage, trigger):
    #ziu_stop_controller()
    signal_ziu("ziu_done": ziu_stage)


def ziu_stage_2(ziu_stage, trigger):
    ziu_start_controller()
    signal_ziu("ziu_done": ziu_stage)


def ziu_stage_3(ziu_stage, trigger):
    sequential_ziu_stage(ziu_stage, ziu_restart_control)


def ziu_stage_4(ziu_stage, trigger):
    sequential_ziu_stage(ziu_stage, ziu_restart_db)


def ziu_stop_controller():
    pass


def ziu_start_controller():
    pass


def ziu_restart_control():
    pass


def ziu_restart_db():
    pass
