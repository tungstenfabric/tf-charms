from charmhelpers.core.hookenv import (
    config,
    log,
    status_set,
    ERROR,
)

import common_utils
import docker_utils


config = config()

MODULE = "openstack-ironic"
BASE_CONFIGS_PATH = "/etc/contrail"

CONFIGS_PATH = BASE_CONFIGS_PATH + "/contrail-openstack-ironic"
IMAGES = [
    "contrail-openstack-ironic-notification-manager",
]
SERVICES = {}


def get_context():
    ctx = {}
    ctx["module"] = MODULE
    ctx["log_level"] = config.get("log-level", "SYS_NOTICE")
    ctx["container_registry"] = config.get("docker-registry")
    ctx["contrail_version_tag"] = config.get("image-tag")
    ctx["contrail_version"] = common_utils.get_contrail_version()
    ips = common_utils.json_loads(config.get("analytics_servers"), list())
    ctx["analytics_servers"] = ips
    ctx["ssl_enabled"] = config.get("ssl_enabled", False)
    ctx["certs_hash"] = common_utils.get_certs_hash(MODULE) if ctx["ssl_enabled"] else ''

    ctx["rabbitmq_user"] = config.get("rabbit-user")
    ctx["rabbitmq_password"] = config.get("rabbit-password")
    ctx["rabbitmq_hostname"] = config.get("rabbit-hostname")
    ctx["rabbitmq_vhost"] = config.get("rabbit-vhost")

    ctx["ironic_notification_level"] = config.get('ironic-notification-level')

    ctx.update(common_utils.json_loads(config.get("orchestrator_info"), dict()))
    if not ctx.get("cloud_orchestrators"):
        ctx["cloud_orchestrators"] = [ctx.get("cloud_orchestrator")] if ctx.get("cloud_orchestrator") else list()

    ctx["config_analytics_ssl_available"] = common_utils.is_config_analytics_ssl_available()
    ctx["logging"] = docker_utils.render_logging()

    log("CTX: {}".format(ctx))

    ctx.update(common_utils.json_loads(config.get("auth_info"), dict()))

    return ctx


def pull_images():
    tag = config.get('image-tag')
    for image in IMAGES:
        try:
            docker_utils.pull(image, tag)
        except Exception as e:
            log("Can't load image {}".format(e), level=ERROR)
            raise Exception('Image could not be pulled: {}:{}'.format(image, tag))


def update_charm_status():
    if config.get("maintenance") or config.get("ziu"):
        return

    ctx = get_context()
    missing_relations = []
    if not ctx.get('rabbitmq_hostname'):
        missing_relations.append("rabbitmq-server:amqp")
    if config.get('tls_present', False) != config.get('ssl_enabled', False):
        missing_relations.append("tls-certificates")
    if missing_relations:
        status_set('blocked',
                   'Missing or incomplete relations: ' + ', '.join(missing_relations))
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

    changed = common_utils.apply_keystone_ca(MODULE, ctx)
    changed |= common_utils.render_and_log(
        "openstack-ironic.env",
        BASE_CONFIGS_PATH + "/common_openstack_ironic.env", ctx)
    changed |= common_utils.render_and_log(
        "/contrail-openstack-ironic.yaml",
        CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(CONFIGS_PATH + "/docker-compose.yaml", changed)

    common_utils.update_services_status(MODULE, SERVICES)


def stop_openstack_ironic():
    docker_utils.compose_down(CONFIGS_PATH + "/docker-compose.yaml")


def remove_created_files():
    common_utils.remove_file_safe(BASE_CONFIGS_PATH + "/common_openstack_ironic.env")
    common_utils.remove_file_safe(CONFIGS_PATH + "/docker-compose.yaml")
