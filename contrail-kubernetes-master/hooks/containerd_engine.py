import datetime
import os
import random
import string
from subprocess import check_call, check_output, DEVNULL
import time
import uuid
import yaml

from charmhelpers.core.hookenv import (
    config,
    log,
    status_set,
    DEBUG,
)
from charmhelpers.core.host import (
    service_restart,
    mkdir,
)
from charmhelpers.core.templating import render
from charmhelpers.fetch import apt_hold, apt_install, apt_update
import container_engine_base


config = config()

CONTAINERD_PACKAGE = 'containerd'
CTR_CLI = "/usr/bin/ctr"
CONTAINERD_NAMESPACE = "default"


class Containerd(container_engine_base.Container):
    def install(self):
        status_set('maintenance', 'Installing containerd via apt')
        apt_update()
        apt_install(CONTAINERD_PACKAGE, fatal=True)
        apt_hold(CONTAINERD_PACKAGE)

    def cp(self, cnt_name, src, dst):
        tmp_dir = "/tmp/" + cnt_name
        os.mkdir(tmp_dir)
        cmd = CTR_CLI + " snapshot mounts " + tmp_dir + " " + cnt_name + " | xargs sudo"
        check_call(cmd, shell=True)
        check_call(["cp", "-r", tmp_dir + src, dst])

    def execute(self, name, cmd, shell=False):
        # ctr task exec --exec-id <exec-id> <container-name> <command>
        exec_id = ''.join(random.choice(string.digits) for _ in range(8))
        cli = [CTR_CLI, "task", "exec", "--exec-id", exec_id, name]
        if isinstance(cmd, list):
            cli.extend(cmd)
        else:
            cli.append(cmd)
        if shell:
            output = check_output(' '.join(cli), shell=True)
        else:
            output = check_output(cli)
        return output.decode('UTF-8')

    def get_image_id(self, image, tag):
        registry = config.get("docker-registry")
        return "{}/{}:{}".format(registry, image, tag)

    def pull(self, image, tag):
        def _check_ctr_presence():
            try:
                check_call([CTR_CLI, "--version"])
                return True
            except Exception:
                return False

        if not _check_ctr_presence():
            status_set("waiting", "Waiting for containerd installation")
            return False
        docker_user = config.get("docker-user")
        docker_password = config.get("docker-password")
        registry_insecure = config.get("docker-registry-insecure")
        image_id = self.get_image_id(image, tag)
        # check image presense
        # use check_output to avoid printing output to log
        output = check_output([CTR_CLI, "image", "check", "name=={}".format(image_id)])
        if output:
            return

        pull_opts = ""
        if docker_user:
            pull_opts += "--user " + docker_user
            if docker_password:
                pull_opts += ":" + docker_password
        if registry_insecure:
            insecure_opts = "-k"
        # pull image. Insert retries to cover issue when image cannot be pulled due to vrouter restart
        for i in range(10):
            try:
                check_call([CTR_CLI, "image", "pull", pull_opts, insecure_opts, self.get_image_id(image, tag)], stdout=DEVNULL)
                break
            except Exception as e:
                log("Cannot pull image {}:{}. {}".format(image, tag, e))

            # retry
            time.sleep(30)

    def compose_run(self, path, config_changed=True):
        do_update = config_changed
        if not do_update:
            # check count of services
            count = None
            with open(path, 'r') as fh:
                data = yaml.load(fh, Loader=yaml.Loader)
                count = len(data['services'])
            # check is it run or not
            cmd = "{} container list -q | grep {}_".format(CTR_CLI, path.split("/")[-2])
            try:
                actual_count = len(check_output(cmd, shell=True).decode("UTF-8").splitlines())
            except Exception:
                actual_count = 0
            log("Services actual count: {}, required count: {}".format(actual_count, count), level=DEBUG)
            do_update = actual_count != count
        if do_update:
            with open(path, "r") as f:
                spec = yaml.load(f, Loader=yaml.Loader)

            # create volumes
            volumes_spec = spec.get("volumes", [])
            if volumes_spec:
                for volume in volumes_spec:
                    self._create_volume(volume[:-1])

            # get containers list to run
            # init_containers run without restart
            services_spec = spec["services"]
            init_containers = []
            running_containers = []
            cnt_name_prefix = path.split("/")[-2] + "_"
            for service in services_spec:
                if "-init" in services_spec[service]["image"]:
                    init_containers.append(service)
                else:
                    running_containers.append(service)

            # start init containers (5 attempts)
            for service in init_containers:
                cnt_name = cnt_name_prefix + service
                for i in range(5):
                    try:
                        log("Running container {}. Attempt {}".format(cnt_name, i))
                        self._run_container(cnt_name, volumes_spec, services_spec, service, detach=False, config_changed=config_changed)
                        break
                    except Exception as e:
                        exc = e
                        if i < 4:
                            try:
                                self.remove_container(cnt_name)
                                self._wait_for_absence(cnt_name)
                            except Exception:
                                pass
                    # retry
                    time.sleep(10)
                else:
                    log("Container {} is not running. {}".format(cnt_name, str(exc)))
                    raise exc

            # start containers that would restart
            for service in running_containers:
                cnt_name = cnt_name_prefix + service
                self._run_container(cnt_name, volumes_spec, services_spec, service, detach=True, config_changed=config_changed)

    def compose_down(self, path):
        with open(path, "r") as f:
            services_spec = yaml.load(f, Loader=yaml.Loader)["services"]

        for service in services_spec:
            cnt_id = self.get_container_id(path, service)
            try:
                self.remove_container(cnt_id)
                self._wait_for_absence(cnt_id)
            except Exception as e:
                log("Error during remove container {}: {}".format(cnt_id, e))

    def compose_kill(self, path, signal, service=None):
        if service:
            services = [service]
        else:
            with open(path, "r") as f:
                services = yaml.load(f, Loader=yaml.Loader)["services"]

        for service in services:
            cnt_id = self.get_container_id(path, service)
            try:
                self.stop_container(cnt_id, signal=signal)
            except Exception as e:
                log("Error during stop container {}: {}".format(cnt_id, e))

    def get_container_id(self, path, service):
        cnt_name = path.split("/")[-2] + "_" + service
        if self._if_container_exists(cnt_name):
            return cnt_name

    def get_container_state(self, path, service):
        # returns None or State dict from docker
        # status must be None when compose returns error or empty ID for service
        cnt_id = self.get_container_id(path, service)
        if not cnt_id:
            return None
        try:
            args = [CTR_CLI, "task", "list"]
            states = check_output(args).decode("UTF-8").rstrip().strip("'")
            for line in states.splitlines()[1:]:
                words = line.split()
                if words[0] == cnt_id:
                    status = words[2]
                    state_json = {"Status": status.lower()}
                    break
            return state_json
        except Exception:
            # let's return None when docker fails to return status by ID or we failed to read provided JSON
            return None

    def stop_container(self, cnt_id, signal="SIGKILL"):
        log("Stopping container {}".format(cnt_id))
        cmd = [CTR_CLI, "task", "kill", "-s", signal, cnt_id]
        check_call(cmd)

    def remove_container(self, cnt_id):
        if self._if_container_exists(cnt_id):
            for i in range(5):
                try:
                    self.stop_container(cnt_id, signal="SIGKILL")
                except Exception as e:
                    log("Cannot stop container {}. {}".format(cnt_id, e))
                try:
                    log("Removing container {}".format(cnt_id))
                    cmd = [CTR_CLI, "container", "rm", cnt_id]
                    check_call(cmd)
                    break
                except Exception as e:
                    exc = e
                    log("Cannot remove container {}. {}".format(cnt_id, e))

                # retry
                time.sleep(5)
            else:
                log("Container {} was not removed. {}".format(cnt_id, str(exc)))
                raise exc

    def create(self, image, tag):
        name = str(uuid.uuid4())
        image_id = self.get_image_id(image, tag)
        args = [CTR_CLI, "container", "create", image_id, name, "/bin/true"]
        check_call(args)
        return name

    def restart_container(self, path, service):
        cnt_id = self.get_container_id(path, service)
        if not cnt_id:
            return None
        self.stop_container(cnt_id)

    def get_contrail_version(self, image, tag, pkg=None):
        # TODO: run container with bash to echo version inside (image inspect was not found for ctr)
        return tag

    def config_changed(self):
        changed = False
        if config.changed("http_proxy") or config.changed("https_proxy") or config.changed("no_proxy"):
            self._render_config()
            changed = True
        return changed

    def render_logging(self):
        return ""

    def _parse_volumes(self, volumes_list, volumes_spec):
        # parse volumes from list [ src:dst, ... ] to crt mount format
        volumes = []
        for mount in volumes_list:
            if "/var/run/docker.sock" in mount:
                src = "/var/run"
                dst = "/var/run"
            else:
                mount_split = mount.split(":")
                src = mount_split[0]
                if src in volumes_spec:
                    src = "/var/lib/contrail/" + src
                dst = mount_split[1]
            mkdir(src, perms=0o755)
            volumes.append("type=bind,src={},dst={},options=rbind:rw".format(src, dst))
        return volumes

    def _create_volume(self, name):
        volumes_dir = "/var/lib/contrail/"
        mkdir(volumes_dir + name, perms=0o755)

    def _run_container(self, cnt_name, volumes_spec, services_spec, service, detach=True, config_changed=True):
        # parse services spec from yaml to container options

        # check if container is already running
        if self._if_container_exists(cnt_name):
            if config_changed:
                self.remove_container(cnt_name)
                self._wait_for_absence(cnt_name)
            else:
                # we shouldn't re-run container if it exists and config didn't changed
                return

        image_id = services_spec[service]["image"]
        if not self._if_image_exists(image_id):
            image_id_separated = image_id.split("/")
            image_name = image_id_separated[-1].split(":")[0]
            image_tag = config.get('image-tag')
            self.pull(image_name, image_tag)
        volumes = []
        parsed_volumes = self._parse_volumes(services_spec[service].get("volumes", []), volumes_spec)
        volumes.extend(parsed_volumes)
        volumes_from = services_spec[service].get("volumes_from", [])
        for serv in volumes_from:
            volumes.extend(self._parse_volumes(services_spec[serv].get("volumes", []), volumes_spec))
        env_dict = services_spec[service].get("environment")
        env_file = services_spec[service].get("env_file")
        # TODO(tikitavi): if cap_add - run with additional capabilities, not privileged
        # TODO: + cni_init container cannot set ulimit, adding privileged mode
        # define which containers need privileged
        privileged = True  # services_spec[service].get("privileged") or services_spec[service].get("cap_add")
        net_host = services_spec[service].get("network_mode") == "host"
        self._run(cnt_name, image_id, volumes, env_dict=env_dict, env_file=env_file,
                  privileged=privileged, net_host=net_host, detach=detach)

    def _run(self, cont_name, image_id, volumes,
             remove=False, env_dict=None, env_file=None, net_host=False,
             privileged=False, detach=True):
        # run container
        args = [CTR_CLI, "run"]
        if detach:
            args.append("-d")
        if remove:
            args.append("--rm")
        if net_host:
            args.append("--net-host")
        if privileged:
            args.append("--privileged")
        for volume in volumes:
            args.extend(["--mount", volume])
        if env_dict:
            for env in env_dict:
                args.extend(["--env", "{}".format(env)])
        if env_file:
            if isinstance(env_file, list):
                # ctr run takes only one env-file in command options
                # concetanating several env_file in single
                file_path = os.path.dirname(env_file[0])
                env_file_name = file_path + "/" + cont_name + ".env"
                self._join_files(env_file, env_file_name)
                args.extend(["--env-file", env_file_name])
            else:
                args.extend(["--env-file", env_file])
        # add namespace to env
        args.extend(["--env", "CONTAINERD_NAMESPACE={}".format(CONTAINERD_NAMESPACE)])

        log_dir = '/var/log/containerd/'  # ???
        mkdir(log_dir, perms=0o755)
        log_file = log_dir + cont_name + '.log'
        # create log file (isn't created automatically)
        with open(log_file, 'a+') as f:
            f.write(datetime.datetime.utcnow().isoformat())
            f.write("\n")
        args.extend(["--log-uri", log_file])
        args.extend([image_id, cont_name])
        log("Running container: {}".format(" ".join(args)))
        check_call(args)
        # we run containers in detach mode if they should restart in case of failure
        if detach:
            cmd = [CTR_CLI, "container", "label", cont_name, "containerd.io/restart.status=running"]
            check_call(cmd)

    def _wait_for_absence(self, cnt_name):
        for i in range(5):
            if not self._if_container_exists(cnt_name):
                return
            time.sleep(2)

    def _if_container_exists(self, cnt_name):
        cmd = [CTR_CLI, "container", "ls", "-q", "id=={}".format(cnt_name)]
        try:
            output = check_output(cmd).decode('UTF-8')
            if len(output) == 0:
                # there is no compose/container/service
                return False
        except Exception:
            # there is no compose/container/service
            return False
        return True

    def _if_image_exists(self, image_id):
        cmd = [CTR_CLI, "image", "ls", "-q", "name=={}".format(image_id)]
        try:
            output = check_output(cmd).decode('UTF-8')
            if len(output) == 0:
                # there is no image
                return False
        except Exception:
            # there is no image
            return False
        return True

    def _render_config(self):
        # From https://docs.docker.com/config/daemon/systemd/#httphttps-proxy
        if len(config.get('no_proxy')) > 2023:
            raise Exception('no_proxy longer than 2023 chars.')
        render('docker-proxy.conf', '/etc/systemd/system/containerd.service.d/proxy.conf', config)
        check_call(['systemctl', 'daemon-reload'])
        service_restart('containerd')

    def _join_files(self, filenames, env_file_name):
        with open(env_file_name, 'w') as outfile:
            for fname in filenames:
                with open(fname) as infile:
                    outfile.write(infile.read())
