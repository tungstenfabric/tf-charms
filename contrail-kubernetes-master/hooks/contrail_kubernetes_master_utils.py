import time
import os
import base64

from charmhelpers.core.hookenv import (
    config,
    log,
    relation_get,
    related_units,
    relation_ids,
    status_set,
    leader_get,
    leader_set,
    charm_dir,
)
from charmhelpers.contrib.charmsupport import nrpe

import common_utils
import docker_utils
from subprocess import check_output


config = config()

MODULE = "kubernetes-master"
BASE_CONFIGS_PATH = "/etc/contrail"

CONFIGS_PATH = BASE_CONFIGS_PATH + "/contrail-kubernetes-master"
IMAGES = [
    "contrail-kubernetes-kube-manager",
]
SERVICES = {
    "kubernetes": [
        "kube-manager",
    ]
}


def kubernetes_token():
    try:
        account_file = os.path.join(charm_dir(), 'files', 'contrail-kubemanager-serviceaccount.yaml')
        check_output(["snap", "run", "kubectl", "--kubeconfig", "/root/.kube/config", "apply", "-f", account_file])
    except Exception as e:
        log("Can't apply manifest for service account: {}".format(e))
        return None
    token_id = None
    for i in range(10):
        try:
            token_id = check_output([
                "snap", "run", "kubectl", "--kubeconfig", "/root/.kube/config", "get", "sa", "contrail-kubemanager", "-n", "contrail",
                "-ogo-template=\"{{(index .secrets 0).name}}\""]).decode('UTF-8').strip('\"')
        except Exception as e:
            log("Can't get SA for contrail-kubemanager {}".format(e))
            return None
        if token_id:
            break
        time.sleep(1)
    if not token_id:
        return None
    try:
        token_64 = check_output([
            "snap", "run", "kubectl", "--kubeconfig", "/root/.kube/config", "get", "secret", token_id, "-n", "contrail",
            "-ogo-template=\"{{.data.token}}\""]).decode('UTF-8').strip('\"')
        token = base64.b64decode(token_64).decode()
        return token
    except Exception as e:
        log("Can't get secret for token: {}".format(e))

    return None


def update_kubernetes_token():
    if leader_get("kube_manager_token"):
        return False
    token = kubernetes_token()
    if not token:
        return False
    leader_set({"kube_manager_token": token})
    return True


def get_context():
    ctx = {}
    ctx["module"] = MODULE
    ctx["log_level"] = config.get("log-level", "SYS_NOTICE")
    ctx["container_registry"] = config.get("docker-registry")
    ctx["contrail_version_tag"] = config.get("image-tag")
    ctx["contrail_version"] = common_utils.get_contrail_version()

    # self IP-s
    kubemanager_ip_list = list()
    for rid in relation_ids("kubernetes-master-cluster"):
        for unit in related_units(rid):
            ip = relation_get("private-address", unit, rid)
            if ip:
                kubemanager_ip_list.append(ip)
    # add it's own ip address
    kubemanager_ip_list.append(common_utils.get_ip())

    ctx["kubemanager_servers"] = kubemanager_ip_list
    # get contrail configuration from relation
    ips = common_utils.json_loads(config.get("controller_ips"), list())
    data_ips = common_utils.json_loads(config.get("controller_data_ips"), list())
    ctx["controller_servers"] = ips
    ctx["control_servers"] = data_ips
    ips = common_utils.json_loads(config.get("analytics_servers"), list())
    ctx["analytics_servers"] = ips
    ctx["analyticsdb_enabled"] = config.get("analyticsdb_enabled", True)
    ctx["ssl_enabled"] = config.get("ssl_enabled", False)

    ctx["cluster_name"] = config.get("cluster_name")
    ctx["cluster_project"] = config.get("cluster_project")
    ctx["cluster_network"] = config.get("cluster_network")
    ctx["pod_subnets"] = config.get("pod_subnets")
    ctx["ip_fabric_subnets"] = config.get("ip_fabric_subnets")
    ctx["service_subnets"] = config.get("service_subnets")
    ctx["ip_fabric_forwarding"] = config.get("ip_fabric_forwarding")
    ctx["ip_fabric_snat"] = config.get("ip_fabric_snat")
    ctx["host_network_service"] = config.get("host_network_service")
    ctx["public_fip_pool"] = config.get("public_fip_pool")

    ctx.update(common_utils.json_loads(config.get("orchestrator_info"), dict()))
    if not ctx.get("cloud_orchestrators"):
        ctx["cloud_orchestrators"] = list(ctx.get("cloud_orchestrator")) if ctx.get("cloud_orchestrator") else list()

    # TODO: switch to use context for this

    ctx["kube_manager_token"] = leader_get("kube_manager_token")
    if config.get("kubernetes_api_hostname") and config.get("kubernetes_api_secure_port"):
        ctx["kubernetes_api_server"] = config.get("kubernetes_api_hostname")
        ctx["kubernetes_api_secure_port"] = config.get("kubernetes_api_secure_port")
    else:
        ctx["kubernetes_api_server"] = config.get("kubernetes_api_server")
        ctx["kubernetes_api_secure_port"] = config.get("kubernetes_api_port")

    ctx["nested_mode"] = config.get("nested_mode")
    if ctx["nested_mode"]:
        # TODO: create  KUBERNETES_NESTED_VROUTER_VIP link-local services in Contrail via config API
        ctx["nested_mode_config"] = common_utils.json_loads(config.get("nested_mode_config"), dict())

    ctx["config_analytics_ssl_available"] = common_utils.is_config_analytics_ssl_available()
    ctx["logging"] = docker_utils.render_logging()

    log("CTX: {}".format(ctx))

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

    if config.get("maintenance") or config.get("ziu"):
        return

    ctx = get_context()
    missing_relations = []
    if not ctx.get("nested_mode") and not ctx.get("controller_servers"):
        missing_relations.append("contrail-controller")
    if not ctx.get("kubernetes_api_server"):
        missing_relations.append("kube-api-endpoint")
    if missing_relations:
        status_set('blocked',
                   'Missing relations: ' + ', '.join(missing_relations))
        return
    if not ctx.get("cloud_orchestrator"):
        status_set('blocked',
                   'Missing cloud_orchestrator info in relation '
                   'with contrail-controller.')
        return
    if not ctx.get("kube_manager_token"):
        status_set('waiting',
                   'Kube manager token is absent. Wait for token from kubectl run.')
        return
    if "openstack" in ctx.get("cloud_orchestrators") and not ctx.get("keystone_ip"):
        status_set('blocked',
                   'Missing auth info in relation with contrail-controller.')
        return

    changed = common_utils.render_and_log(
        "kubemanager.env",
        BASE_CONFIGS_PATH + "/common_kubemanager.env", ctx)
    changed |= common_utils.render_and_log(
        "/contrail-kubemanager.yaml",
        CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(CONFIGS_PATH + "/docker-compose.yaml", changed)

    common_utils.update_services_status(MODULE, SERVICES)


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


def stop_kubernetes_master():
    docker_utils.compose_down(CONFIGS_PATH + "/docker-compose.yaml")


def remove_created_files():
    common_utils.remove_file_safe(BASE_CONFIGS_PATH + "/common_kubemanager.env")
    common_utils.remove_file_safe(CONFIGS_PATH + "/docker-compose.yaml")
