import os
import base64
import uuid

from distutils.dir_util import copy_tree
import shutil

from charmhelpers.core.hookenv import (
    config,
    log,
    status_set
)

import common_utils
import docker_utils
from subprocess import (
    check_call,
    check_output
)


config = config()

MODULE = "command"
BASE_CONFIGS_PATH = "/etc/contrail"

CONFIGS_PATH = BASE_CONFIGS_PATH + "/contrail-command"
IMAGES = [
    "contrail-command-deployer",
    "contrail-command"
]
SERVICES = {}


def get_context():
    ctx = {}
    ctx["module"] = MODULE
    ctx["log_level"] = config.get("log-level", "SYS_NOTICE")
    ctx["container_registry"] = config.get("docker-registry")
    ctx["container_tag"] = config.get("image-tag")

    ctx["command_ip"] = config.get("command-ip")
    ctx["vrouter_gateway"] = config.get("vrouter-gateway")
    ctx["contrail_container_tag"] = config.get("contrail-container-tag")
    ctx["install_docker"] = config.get("install-docker")

    ctx["delete_db"] = config.get("delete-db")
    ctx["persist_rules"] = config.get("persist-rules")
    ctx["juju_controller"] = config.get("juju-controller")
    ctx["juju_cacert_path"] = _decode_cert("juju-ca-cert")
    ctx["juju_model_id"] = config.get("juju-model-id")
    ctx["juju_controller_password"] = config.get("juju-controller-password")
    ctx["juju_controller_user"] = config.get("juju-controller-user")

    ctx.update(common_utils.json_loads(config.get("orchestrator_info"),
                                       dict()))

    log("CTX: {}".format(ctx))
    return ctx


def _decode_cert(key):
    val = config.get(key)
    if not val:
        return None
    try:
        with open('/tmp/juju_ca_cert.pem', 'w') as f:
            f.write(base64.b64decode(val).decode())
        return '/tmp/juju_ca_cert.pem'
    except Exception as e:
        log("Couldn't decode certificate from config['{}']: {}".format(
            key, str(e)), level='ERROR')
    return None


def deploy_ccd_code(image, tag):
    docker_utils.remove_container_by_image(image)

    name = docker_utils.create(image, tag)
    try:
        src = '/' + image
        tmp_folder = os.path.join('/tmp', str(uuid.uuid4()))
        docker_utils.cp(name, src, tmp_folder)
        try:
            os.mkdir(tmp_folder + '/docker')
            os.mkdir('/etc/ansible')
        except Exception:
            pass

        docker_utils.cp(name, '/bin/deploy_contrail_command',
                        tmp_folder + '/docker/')
        docker_utils.cp(name, '/etc/ansible/ansible.cfg', '/etc/ansible/')

        dst = '/' + image
        copy_tree(tmp_folder, dst)

        shutil.rmtree(tmp_folder, ignore_errors=True)
    finally:
        docker_utils.remove_container_by_image(image)


def update_status():
    command_ip = config.get("command-ip")

    try:
        output = check_output(
            "curl -k https://{}:8079 | grep '<title>'".format(command_ip),
            shell=True).decode('UTF-8')
    except Exception:
        status_set("waiting", "Cannot curl to " + command_ip + ":8079")
        return False
    if 'Contrail Command' not in output:
        status_set("waiting", "Cannot curl to " + command_ip + ":8079")
        return False

    status_set("active", "Unit is ready")
    return True


def update_charm_status(import_cluster=False):
    tag = config.get('image-tag')

    ctx = get_context()

    for image in IMAGES:
        try:
            docker_utils.pull(image, tag)
        except Exception as e:
            log("Can't load image {}".format(e))
            status_set('blocked',
                       'Image could not be pulled: {}:{}'.format(image, tag))
            return

    if not ctx.get("juju_controller"):
        status_set('blocked',
                   'Missing juju-controller parameter in config')
        return
    if not ctx.get("juju_cacert_path"):
        status_set('blocked',
                   'Missing juju-ca-cert parameter in config')
        return
    if not ctx.get("juju_model_id"):
        status_set('blocked',
                   'Missing juju-model-id parameter in config')
        return
    if not ctx.get("juju_controller_password"):
        status_set('blocked',
                   'Missing juju-controller-password parameter in config')
        return
    if not ctx.get("cloud_orchestrator"):
        status_set('blocked',
                    'Missing cloud orchestrator info in relations.')
    if ctx.get("cloud_orchestrator") != "openstack":
        status_set('blocked',
                    'Contrail command works with openstack only now')

    deployer_image = "contrail-command-deployer"
    changed = common_utils.render_and_log("min_config.yaml",
                                          '/cluster_config.yml', ctx)
    env = common_utils.render_and_log("juju_environment",
                                      '/tmp/juju_environment', ctx)
    if changed or env or import_cluster:
        deploy_ccd_code(deployer_image, tag)
        if not ctx.get("cloud_orchestrator"):
            import_cluster = False
        elif ctx.get("cloud_orchestrator") != "openstack":
            import_cluster = False
        else:
            import_cluster = True
        run_contrail_command(deployer_image, import_cluster)
        # do not update status if no relation to contrail-controller
        if not import_cluster:
            return

    update_status()


def run_contrail_command(deployer_image, import_cluster):
    dst = '/' + deployer_image
    export_env = 'export HOME=/root ; '
    if import_cluster:
        export_env = '. /tmp/juju_environment ; '

    check_call(export_env + dst + '/docker/deploy_contrail_command',
               shell=True)
