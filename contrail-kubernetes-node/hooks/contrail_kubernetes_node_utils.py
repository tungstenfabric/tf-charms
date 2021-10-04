from charmhelpers.core.hookenv import (
    config,
    status_set,
    log,
    ERROR,
)
import common_utils


config = config()

MODULE = "kubernetes-node"
BASE_CONFIGS_PATH = "/etc/contrail"

CONFIGS_PATH = BASE_CONFIGS_PATH + "/contrail-kubernetes-node"
IMAGES = [
    "contrail-kubernetes-cni-init",
]


def get_context():
    ctx = {}
    ctx["module"] = MODULE
    ctx["log_level"] = config.get("log-level", "SYS_NOTICE")
    ctx["container_registry"] = config.get("docker-registry")
    ctx["contrail_version_tag"] = config.get("image-tag")

    ctx["cluster_name"] = config.get("cluster_name")
    ctx["nested_mode"] = config.get("nested_mode")
    if ctx["nested_mode"]:
        ctx["nested_mode_config"] = common_utils.json_loads(config.get("nested_mode_config"), dict())

    ctx["logging"] = common_utils.container_engine().render_logging()

    log("CTX: {}".format(ctx))
    return ctx


def pull_images():
    tag = config.get('image-tag')
    for image in IMAGES:
        try:
            common_utils.container_engine().pull(image, tag)
        except Exception as e:
            log("Can't load image {}".format(e), level=ERROR)
            raise Exception('Image could not be pulled: {}:{}'.format(image, tag))


def update_charm_status():
    ctx = get_context()
    missing_relations = []
    if config.get('container_runtime') == "containerd" and not config.get('containerd_present'):
        missing_relations.append("containerd")
    if missing_relations:
        status_set('blocked',
                   'Missing or incomplete relations: ' + ', '.join(missing_relations))
        return

    changed = common_utils.render_and_log(
        "cni.env",
        BASE_CONFIGS_PATH + "/common_cni.env", ctx)
    changed |= common_utils.render_and_log(
        "/contrail-cni.yaml",
        CONFIGS_PATH + "/docker-compose.yaml", ctx)
    common_utils.container_engine().compose_run(CONFIGS_PATH + "/docker-compose.yaml", changed)

    status_set("active", "Unit is ready")


def stop_kubernetes_node():
    common_utils.container_engine().compose_down(CONFIGS_PATH + "/docker-compose.yaml")


def remove_created_files():
    common_utils.remove_file_safe(BASE_CONFIGS_PATH + "/common_cni.env")
    common_utils.remove_file_safe(CONFIGS_PATH + "/docker-compose.yaml")
