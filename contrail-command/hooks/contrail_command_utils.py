import os
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

    ctx["command_ip"] = common_utils.get_ip()
    ctx["contrail_container_tag"] = config.get("image-tag")

    ctx.update(common_utils.json_loads(config.get("orchestrator_info"),
                                       dict()))

    log("CTX: {}".format(ctx))
    return ctx


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
    command_ip = common_utils.get_ip()

    try:
        output = check_output(
            "curl -k https://{}:8079 | grep '<title>'".format(command_ip),
            shell=True).decode('UTF-8')
    except Exception:
        status_set("waiting", "URL is not ready {}:8079".format(command_ip))
        return False
    if 'Contrail Command' not in output:
        status_set("waiting", "URL is not ready {}:8079".format(command_ip))
        return False

    status_set("active", "Unit is ready")
    return True


def update_charm_status():
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

    deployer_image = "contrail-command-deployer"
    deploy_ccd_code(deployer_image, tag)

    if not ctx.get("cloud_orchestrator"):
        status_set('blocked', 'Missing cloud orchestrator info in relations.')
        return
    elif ctx.get("cloud_orchestrator") != "openstack":
        status_set('blocked', 'Contrail command works with openstack only now')
        return

    changed = common_utils.render_and_log('cluster_config.yml.j2', '/cluster_config.yml', ctx)

    if changed or not config.get("command_deployed"):
        dst = '/' + deployer_image + '/docker/deploy_contrail_command'
        check_call('./files/deploy_contrail_command.sh ' + dst, shell=True)
        config["command_deployed"] = True

    update_status()


def import_cluster(juju_params):
    if not update_status():
        return False, 'Unit is not ready, try later'

    common_utils.render_and_log('juju_environment', '/tmp/juju_environment', juju_params)
    deployer_image = "contrail-command-deployer"
    dst = '/' + deployer_image + '/docker/deploy_contrail_command'
    try:
        check_call('. /tmp/juju_environment ; ./files/deploy_contrail_command.sh ' + dst, shell=True)
        status_set('active', 'Cluster is imported')
    except Exception as e:
        return False, 'Import failed ({}). Please check logs'.format(e)

    return True, "Success"
