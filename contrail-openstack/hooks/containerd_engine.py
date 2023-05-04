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
    service_start,
    service_restart,
    service_stop,
    service_running,
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
        os.makedirs(tmp_dir, mode=0o755, exist_ok=True)
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
                check_call([CTR_CLI, "--version"], stderr=DEVNULL)
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

        cmd = [CTR_CLI, "image", "pull"]
        if docker_user and docker_password:
            cmd.append("--user")
            cmd.append(docker_user + ":" + docker_password)
        if registry_insecure:
            cmd.append("-k")
        cmd.append(image_id)
        # pull image. Insert retries to cover issue when image cannot be pulled due to vrouter restart
        for i in range(10):
            try:
                check_call(cmd, stdout=DEVNULL)
                break
            except Exception as e:
                log("Cannot pull image {}:{}. {}".format(image, tag, e))

            # retry
            time.sleep(30)

    def compose_run(self, path, config_changed=True):
        cnt_name_prefix = path.split("/")[-2]
        do_update = config_changed
        if not do_update:
            # check count of services
            count = None
            with open(path, 'r') as fh:
                data = yaml.load(fh, Loader=yaml.Loader)
                count = len(data['services'])
            # check is it run or not
            cmd = "{} task list -q | grep {}-".format(CTR_CLI, cnt_name_prefix)
            try:
                actual_count = len(check_output(cmd, shell=True).decode("UTF-8").splitlines())
            except Exception:
                actual_count = 0
            log("Services actual count: {}, required count: {}".format(actual_count, count), level=DEBUG)
            do_update = actual_count != count
        if do_update:
            with open(path, "r") as f:
                spec = yaml.load(f, Loader=yaml.Loader)

            # get containers list to run
            # init_containers run without restart
            services_spec = spec["services"]
            volumes_spec = spec.get("volumes", [])

            # start containers
            self._create_systemd_target(cnt_name_prefix)
            for service in services_spec:
                cnt_name = cnt_name_prefix + "-" + service
                cnt_config = self._parse_config(cnt_name, volumes_spec, services_spec, service)
                image_id = cnt_config["image_id"]
                if not self._if_image_exists(image_id):
                    self._image_pull(image_id)
                self._create_container(cnt_config)
                self._create_systemd_service(cnt_name_prefix, cnt_config)
            self._run_systemd_service(cnt_name_prefix)

    def compose_down(self, path, services_to_wait=[]):
        with open(path, "r") as f:
            services_spec = yaml.load(f, Loader=yaml.Loader)["services"]

        if services_to_wait:
            # kill containers with SIGQUIT
            for service in list(services_to_wait):
                cnt_id = self.get_container_id(path, service)
                if cnt_id:
                    self._kill_container(cnt_id, signal="SIGQUIT")

            # check if containers were stopped
            for service in list(services_to_wait):
                state = self.get_container_state(path, service)
                if not state or state.get('Status', '').lower() != 'running':
                    services_to_wait.remove(service)
            # if not raise Exception
            if services_to_wait:
                raise Exception("{} do not react to SIGQUIT. please check it manually and re-run operation.".format(", ".join(services_to_wait)))

        for service in services_spec:
            cnt_id = self.get_container_id(path, service)
            if not cnt_id:
                continue
            self._stop_container(cnt_id)
            try:
                self.remove_container(cnt_id)
                self._wait_for_absence(cnt_id)
            except Exception as e:
                log("Error during remove container {}: {}".format(cnt_id, e))

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

    def _kill_container(self, cnt_id, signal="SIGTERM"):
        log("Stopping container {}".format(cnt_id))
        wait_config = {
            'wait_for_stop': True,
            'name': cnt_id,
            'kill_signal': signal
        }
        render("service_stop.sh", "/etc/contrail/" + cnt_id + "_stop.sh", wait_config, perms=0o755)
        self._daemon_reload
        service_stop(cnt_id)
        # TODO: do we need to rewrite stop script back?

    def _stop_container(self, cnt_id):
        log("Stopping container {}".format(cnt_id))
        service_stop(cnt_id)

    def remove_container(self, cnt_id):
        if self._if_container_exists(cnt_id):
            self._stop_container(cnt_id)
            for i in range(3):
                try:
                    log("Removing container {}. Try {}".format(cnt_id, i))
                    cmd = [CTR_CLI, "container", "rm", cnt_id]
                    check_call(cmd)
                    break
                except Exception as e:
                    exc = e
                # retry
                time.sleep(3)
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
        service_stop(cnt_id)
        service_start(cnt_id)

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

    # systemd
    def _daemon_reload(self):
        cmd = ["systemctl", "daemon-reload"]
        check_call(cmd)

    def _create_systemd_target(self, group_name):
        params = {
            "group_name": group_name
        }
        render("target.tmpl", "/etc/systemd/system/" + group_name + ".service", params)
        self._enable_systemd_service(group_name)

    def _create_systemd_service(self, group_name, cnt_config):
        cnt_config["group_name"] = group_name
        render("service.tmpl", "/etc/systemd/system/" + cnt_config["name"] + ".service", cnt_config)
        render("service_stop.sh", "/etc/contrail/" + cnt_config["name"] + "_stop.sh", cnt_config, perms=0o755)
        self._daemon_reload()
        self._enable_systemd_service(cnt_config["name"])

    def _enable_systemd_service(self, service):
        cmd = ["systemctl", "enable", service]
        check_call(cmd)

    def _run_systemd_service(self, service):
        log("Starting service {}".format(service))
        service_start(service)
        if not service_running(service):
            raise Exception("Service {} didn't start".format(service))

    def _remove_task(self, cnt_id):
        cmd = [CTR_CLI, "task", "rm", cnt_id]
        check_call(cmd, stderr=DEVNULL)

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
            if not os.path.exists(src):
                os.makedirs(src, mode=0o755, exist_ok=True)
            volumes.append("type=bind,src={},dst={},options=rbind:rw".format(src, dst))
        return volumes

    def _parse_config(self, cnt_name, volumes_spec, services_spec, service):
        # parse services spec from yaml
        cnt_config = {}
        cnt_config["name"] = cnt_name
        cnt_config["image_id"] = services_spec[service]["image"]
        volumes = []
        parsed_volumes = self._parse_volumes(services_spec[service].get("volumes", []), volumes_spec)
        volumes.extend(parsed_volumes)
        volumes_from = services_spec[service].get("volumes_from", [])
        for serv in volumes_from:
            volumes.extend(self._parse_volumes(services_spec[serv].get("volumes", []), volumes_spec))
        cnt_config["volumes"] = volumes
        cnt_config["env_dict"] = services_spec[service].get("environment")
        cnt_config["env_file"] = services_spec[service].get("env_file")
        cnt_config["privileged"] = services_spec[service].get("privileged")
        cnt_config["net_host"] = services_spec[service].get("network_mode") == "host"
        cnt_config["pid_host"] = services_spec[service].get("pid") == "host"
        cnt_config["entrypoint"] = services_spec[service].get("entrypoint")
        cnt_config["restart"] = services_spec[service].get("restart", 'no')
        cnt_config["after_services"] = services_spec[service].get("depends_on")

        return cnt_config

    def _create_container(self, cnt_config):
        # run container
        changed = False
        cnt_name = cnt_config.get("name")
        args = [CTR_CLI, "container", "create"]
        if cnt_config.get("net_host"):
            args.append("--net-host")
        if cnt_config.get("pid_host"):
            args.extend(["--with-ns", "pid:/proc/1/ns/pid"])
        if cnt_config.get("privileged"):
            args.append("--privileged")
        for volume in cnt_config.get("volumes"):
            args.extend(["--mount", volume])

        env_dict = cnt_config.get("env_dict")
        env_file = cnt_config.get("env_file")
        if env_dict or env_file:
            env_filename = "/etc/contrail/" + cnt_name + ".env"
            self._get_env(env_filename, env_dict, env_file)
            changed |= self._if_changed(env_filename)
            args.extend(["--env-file", env_filename])
        args.append("--")
        args.extend([cnt_config["image_id"], cnt_name])
        if cnt_config.get("entrypoint"):
            args.extend(cnt_config["entrypoint"])
        run_filename = '/etc/contrail/' + cnt_name + '.run'
        with open(run_filename, 'w') as f:
            f.write(" ".join(args))
        changed |= self._if_changed(run_filename)

        if self._if_container_exists(cnt_name) and not changed:
            os.remove(env_filename)
            os.remove(run_filename)
            return

        # check if container is already running
        if self._if_container_exists(cnt_name):
            self.remove_container(cnt_name)
            self._wait_for_absence(cnt_name)

        log("Creating container: {}".format(" ".join(args)))
        check_call(args)

        os.replace(run_filename, run_filename + ".current")
        if env_filename:
            os.replace(env_filename, env_filename + ".current")

    def _get_env(self, filename, env_dict, env_files):
        with open(filename, 'w') as outfile:
            outfile.write("# env file is autogenerated, do not edit manually\n")
        if env_files:
            if isinstance(env_files, str):
                env_files = [env_files]
            self._join_files(env_files, filename)
        if env_dict:
            with open(filename, 'a+') as outfile:
                for env in env_dict:
                    outfile.write(env)
                    outfile.write('\n')
        # add CONTAINERD_NAMESPACE var to containers
        with open(filename, 'a+') as outfile:
            # TODO: check if possible to detect namespace from inside container
            outfile.write("CONTAINERD_NAMESPACE={}\n".format(CONTAINERD_NAMESPACE))

    def _get_file(self, filename):
        try:
            with open(filename) as f:
                file_lines = set(f.readlines())
        except Exception:
            file_lines = set()

        return file_lines

    def _if_changed(self, filename):
        """Returns True if configuration has been changed."""
        old_lines = self._get_file(filename + ".current")
        new_lines = self._get_file(filename)
        new_set = new_lines.difference(old_lines)
        old_set = old_lines.difference(new_lines)

        return bool(new_set or old_set)

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

    def _image_pull(self, image_id):
        image_id_separated = image_id.split("/")
        image_name = image_id_separated[-1].split(":")[0]
        image_tag = config.get('image-tag')
        self.pull(image_name, image_tag)

    def _render_config(self):
        # From https://docs.docker.com/config/daemon/systemd/#httphttps-proxy
        if len(config.get('no_proxy')) > 2023:
            raise Exception('no_proxy longer than 2023 chars.')
        render('docker-proxy.conf', '/etc/systemd/system/containerd.service.d/proxy.conf', config)
        check_call(['systemctl', 'daemon-reload'])
        service_restart('containerd')

    def _join_files(self, filenames, env_filename):
        with open(env_filename, 'a+') as outfile:
            for fname in filenames:
                with open(fname) as infile:
                    outfile.write(infile.read())
                    outfile.write('\n\n')
