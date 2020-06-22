import os
import socket
import yaml
from subprocess import (
    check_call,
    check_output,
)
import netifaces
from charmhelpers.core.hookenv import (
    config,
    log,
    in_relation_hook,
    status_set,
    unit_get,
    related_units,
    relation_ids,
    relation_get,
    relation_set,
    WARNING,
)

from charmhelpers.core.host import (
    fstab_mount,
    umount,
    service_restart,
    get_total_ram,
    lsb_release,
    mkdir,
    write_file,
)
from charmhelpers.core import fstab
from charmhelpers.core import sysctl
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.core.templating import render
import common_utils
import docker_utils


MODULE = "agent"
BASE_CONFIGS_PATH = "/etc/contrail"

CONFIGS_PATH = BASE_CONFIGS_PATH + "/vrouter"
IMAGES = [
    "contrail-node-init",
    "contrail-nodemgr",
    "contrail-vrouter-agent",
]
# images for new versions that can be absent in previous releases
IMAGES_OPTIONAL = [
    "contrail-provisioner",
]
IMAGES_KERNEL = [
    "contrail-vrouter-kernel-build-init",
]
IMAGES_DPDK = [
    "contrail-vrouter-kernel-init-dpdk",
    "contrail-vrouter-agent-dpdk",
]
SERVICES = {
    "vrouter": [
        "agent",
        "nodemgr"
    ]
}

DPDK_ARGS = {
    "dpdk-main-mempool-size": "--vr_mempool_sz",
    "dpdk-pmd-txd-size": "--dpdk_txd_sz",
    "dpdk-pmd-rxd-size": "--dpdk_rxd_sz",
    "dpdk-rx-ring-sz": "--vr_dpdk_rx_ring_sz",
    "dpdk-tx-ring-sz": "--vr_dpdk_tx_ring_sz",
    "dpdk-yield-option": "-–yield_option"
}

config = config()


def _get_dpdk_args():
    result = []
    for arg in DPDK_ARGS:
        val = config.get(arg)
        if val:
            result.append("{} {}".format(DPDK_ARGS[arg], val))
    return " ".join(result)


def _get_hugepages():
    pages = config.get("dpdk-hugepages")
    if not pages:
        return None
    if not pages.endswith("%"):
        return pages
    pp = int(pages.rstrip("%"))
    return int(get_total_ram() * pp / 100 / 1024 / 2048)


def _get_default_gateway_iface():
    # TODO: get iface from route to CONTROL_NODES
    if hasattr(netifaces, "gateways"):
        return netifaces.gateways()["default"][netifaces.AF_INET][1]

    data = check_output("ip route | grep ^default", shell=True).decode('UTF-8').split()
    return data[data.index("dev") + 1]


def _get_iface_gateway_ip(iface):
    ifaces = [iface, "vhost0"]
    for line in check_output(["route", "-n"]).decode('UTF-8').splitlines()[2:]:
        items = line.split()
        if "G" in items[3] and items[7] in ifaces:
            log("Found gateway {} for interface {}".format(items[1], iface))
            return items[1]
    log("vrouter-gateway set to 'auto' but gateway could not be determined "
        "from routing table for interface {}".format(iface), level=WARNING)
    return None


# Convert mask like "0xABCD" to number format like "1,2,3-5,16"
# ============================================
# tt = {
#   "0x01": "0",
#   "0x03": "0,1",
#   "0x80018001": "0,15,16,31",
#   "0x80000000": "31",
#   "0x0F0F0F0F": "0-3,8-11,16-19,24-27",
#   "0xF0F0F0F0": "4-7,12-15,20-23,28-31",
#   "0xC003B019": "0,3,4,12,13,15-17,30,31",
#   "0,2-3": "0,2-3"
# }
# for k, v in tt.items():
#     r = _convert2cpuset(k)
#     print(k, v, r)
#     assert(v == r)
# ============================================
def _convert2cpuset(cpuset):
    if not cpuset or not cpuset.startswith("0x"):
        return cpuset
    cpuset_int = int(cpuset, 16)
    cpuset = ""
    mask = 1
    i = 0
    while i < 64:
        start = i
        while (cpuset_int & mask != 0) and i < 64:
            i += 1
            mask <<= 1
        if i == start:
            i += 1
            mask <<= 1
            continue
        if cpuset:
            cpuset += ","
        if i - start > 2:
            cpuset += "{}-{}".format(start, i - 1)
        elif i - start > 1:
            cpuset += "{},{}".format(start, i - 1)
        else:
            cpuset += "{}".format(start)
    return cpuset


def get_context():
    ctx = {}
    ctx["module"] = MODULE
    ctx["ssl_enabled"] = config.get("ssl_enabled", False)
    ctx["log_level"] = config.get("log-level", "SYS_NOTICE")
    ctx["container_registry"] = config.get("docker-registry")
    ctx["contrail_version_tag"] = config.get("image-tag")
    ctx["sriov_physical_interface"] = config.get("sriov-physical-interface")
    ctx["sriov_numvfs"] = config.get("sriov-numvfs")
    ctx["max_vm_flows"] = config.get("max-vm-flows")
    ctx["contrail_version"] = common_utils.get_contrail_version()

    # NOTE: charm should set non-fqdn hostname to be compatible with R5.0 deployments
    ctx["hostname"] = socket.getfqdn() if config.get("hostname-use-fqdn", True) else socket.gethostname()
    iface = config.get("physical-interface")
    ctx["physical_interface"] = iface
    gateway_ip = config.get("vhost-gateway")
    if gateway_ip == "auto":
        gateway_ip = _get_iface_gateway_ip(iface)
    ctx["vrouter_gateway"] = gateway_ip if gateway_ip else ''

    ctx["agent_mode"] = "dpdk" if config["dpdk"] else "kernel"
    if config["dpdk"]:
        ctx["dpdk_additional_args"] = _get_dpdk_args()
        ctx["dpdk_driver"] = config.get("dpdk-driver")
        ctx["dpdk_coremask"] = config.get("dpdk-coremask")
        ctx["dpdk_service_coremask"] = config.get("dpdk-service-coremask")
        ctx["dpdk_ctrl_thread_coremask"] = config.get("dpdk-ctrl-thread-coremask")
        cpuset = _convert2cpuset(config.get("dpdk-ctrl-thread-coremask"))
        if cpuset:
            ctx["agent_containers_cpuset"] = cpuset
        ctx["dpdk_hugepages"] = _get_hugepages()
    else:
        ctx["hugepages_1g"] = config.get("kernel-hugepages-1g")
        ctx["hugepages_2m"] = config.get("kernel-hugepages-2m")

    ctx.update(tsn_ctx())

    info = common_utils.json_loads(config.get("orchestrator_info"), dict())
    ctx.update(info)

    ctx["controller_servers"] = common_utils.json_loads(config.get("controller_ips"), list())
    ctx["control_servers"] = common_utils.json_loads(config.get("controller_data_ips"), list())
    ctx["analytics_servers"] = common_utils.json_loads(config.get("analytics_servers"), list())
    ctx["config_analytics_ssl_available"] = common_utils.is_config_analytics_ssl_available()

    if "plugin-ips" in config:
        plugin_ips = common_utils.json_loads(config["plugin-ips"], dict())
        my_ip = unit_get("private-address")
        if my_ip in plugin_ips:
            ctx["plugin_settings"] = plugin_ips[my_ip]

    if config.get('maintenance') == 'issu':
        ctx["controller_servers"] = common_utils.json_loads(config.get("issu_controller_ips"), list())
        ctx["control_servers"] = common_utils.json_loads(config.get("issu_controller_data_ips"), list())
        ctx["analytics_servers"] = common_utils.json_loads(config.get("issu_analytics_ips"), list())
        # orchestrator_info and auth_info can be taken from old relation

    ctx["logging"] = docker_utils.render_logging()
    log("CTX: " + str(ctx))

    ctx.update(common_utils.json_loads(config.get("auth_info"), dict()))
    return ctx


def _pull_images():
    tag = config.get('image-tag')
    for image in IMAGES + (IMAGES_DPDK if config["dpdk"] else IMAGES_KERNEL):
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


def update_charm_status():
    fix_dns_settings()
    _pull_images()

    if config.get("maintenance"):
        log("Maintenance is in progress")
        common_utils.update_services_status(MODULE, SERVICES)
        return

    ctx = get_context()
    if not _check_readyness(ctx):
        return
    _run_services(ctx)


def _check_readyness(ctx):
    missing_relations = []
    if not ctx.get("controller_servers"):
        missing_relations.append("contrail-controller")
    if config.get("wait-for-external-plugin", False) and "plugin_settings" not in ctx:
        missing_relations.append("vrouter-plugin")
    if missing_relations:
        status_set('blocked',
                   'Missing relations: ' + ', '.join(missing_relations))
        return False
    if not ctx.get("analytics_servers"):
        status_set('blocked',
                   'Missing analytics_servers info in relation '
                   'with contrail-controller.')
        return False
    if not ctx.get("cloud_orchestrator"):
        status_set('blocked',
                   'Missing cloud_orchestrator info in relation '
                   'with contrail-controller.')
        return False
    if ctx.get("cloud_orchestrator") == "openstack" and not ctx.get("keystone_ip"):
        status_set('blocked',
                   'Missing auth info in relation with contrail-controller.')
        return False
    if ctx.get("cloud_orchestrator") == "kubernetes" and not ctx.get("kube_manager_token"):
        status_set('blocked',
                   'Kube manager token undefined.')
        return False
    if ctx.get("cloud_orchestrator") == "kubernetes" and not ctx.get("kubernetes_api_server"):
        status_set('blocked',
                   'Kubernetes API unavailable')
        return False

    # TODO: what should happens if relation departed?
    return True


def _run_services(ctx):
    # local file for vif utility
    common_utils.render_and_log(
        "contrail-vrouter-agent.conf",
        "/etc/contrail/contrail-vrouter-agent.conf", ctx, perms=0o440)

    changed = common_utils.apply_keystone_ca(MODULE, ctx)
    changed |= common_utils.render_and_log(
        "vrouter.env",
        BASE_CONFIGS_PATH + "/common_vrouter.env", ctx)
    changed |= common_utils.render_and_log("vrouter.yaml", CONFIGS_PATH + "/docker-compose.yaml", ctx)
    docker_utils.compose_run(CONFIGS_PATH + "/docker-compose.yaml", changed)

    if is_reboot_required():
        status_set('blocked',
                   'Reboot is required due to hugepages allocation.')
        return
    common_utils.update_services_status(MODULE, SERVICES)


def stop_agent():
    path = CONFIGS_PATH + "/docker-compose.yaml"
    docker_utils.compose_kill(path, "SIGQUIT", "vrouter-agent")
    # wait for exited code for vrouter-agent. Each 5 seconds, max wait 1 minute
    for i in range(0, 12):
        state = docker_utils.get_container_state(path, "vrouter-agent")
        if not state or state.get('Status', '').lower() != 'running':
            break
    else:
        raise Exception("vrouter-agent do not react to SIGQUIT. please check it manually and re-run operation.")
    docker_utils.compose_down(path)
    # remove all built vrouter.ko
    modules = '/lib/modules'
    for item in os.listdir(modules):
        path = os.path.join(modules, item, 'updates/dkms/vrouter.ko')
        try:
            os.remove(path)
        except Exception:
            pass


def action_upgrade():
    mode = config.get("maintenance")
    if not mode:
        return

    stop_agent()
    if mode == 'issu':
        _run_services(get_context())
    elif mode == 'ziu':
        update_ziu("upgrade")


def fix_dns_settings():
    # in some bionic installations DNS is proxied by local instance
    # of systed-resolved service. this services applies DNS settings
    # that was taken overDHCP to exact interface - ens3 for example.
    # and when we move traffic from ens3 to vhost0 then local DNS
    # service stops working correctly because vhost0 doesn't have
    # upstream DNS server setting.
    # while we don't know how to move DNS settings to vhost0 in
    # vrouter-agent container - let's remove local DNS proxy from
    # the path and send DNS requests directly to the HUB.
    # this situation is observed only in bionic.
    if lsb_release()['DISTRIB_CODENAME'] != 'bionic':
        return
    if os.path.exists('/run/systemd/resolve/resolv.conf'):
        os.remove('/etc/resolv.conf')
        os.symlink('/run/systemd/resolve/resolv.conf', '/etc/resolv.conf')


def fix_libvirt():
    # do some fixes for libvirt with DPDK
    # it's not required for non-DPDK deployments

    # add apparmor exception for huge pages
    check_output([
        "sed", "-E", "-i", "-e",
        "\!^[[:space:]]*owner \"/run/hugepages/kvm/libvirt/qemu/\*\*\" rw"
        "!a\\\n  owner \"/hugepages/libvirt/qemu/**\" rw,",
        "/etc/apparmor.d/abstractions/libvirt-qemu"])

    if lsb_release()['DISTRIB_CODENAME'] == 'xenial':
        # fix libvirt tempate for xenial
        render("TEMPLATE.qemu",
               "/etc/apparmor.d/libvirt/TEMPLATE.qemu",
               dict())
        libvirt_file = '/etc/apparmor.d/abstractions/libvirt-qemu'
        with open(libvirt_file) as f:
            data = f.readlines()
        new_line = "/run/vrouter/* rw,"
        for line in data:
            if new_line in line:
                break
        else:
            with open(libvirt_file, "a") as f:
                f.write("\n  " + new_line + "\n")

    service_restart("apparmor")
    check_call(["/etc/init.d/apparmor", "reload"])


def _get_hp_options(name):
    nr = config.get(name, "")
    return int(nr) if nr and nr != "" else 0


def reboot():
    log("Schedule rebooting the node")
    check_call(["juju-reboot"])


def is_reboot_required():
    # now checks only if 1gb hugepages is configured but not present in the system
    # TODO: maybe check /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages and nr_hugepages for 2mb pages
    p_1g = _get_hp_options("kernel-hugepages-1g")
    if p_1g == 0:
        return False

    # check current settings, for example:
    # cat /proc/cmdline
    # BOOT_IMAGE=/boot/vmlinuz-4.15.0-99-generic root=UUID=f343d78d-5f18-4723-a662-48db742bdc6a ro default_hugepagesz=1G hugepagesz=1G hugepages=2 hugepagesz=2M hugepages=1024

    data = check_output(['cat', '/proc/cmdline']).decode('UTF-8').split()
    i = 0
    while i < len(data):
        if data[i] == 'hugepagesz=1G' and i + 1 < len(data) and data[i + 1].startswith('hugepages='):
            try:
                amount = int(data[i + 1].split('=')[1])
            except ValueError:
                amount = 0
            return amount < p_1g
        i += 1

    return True


def _del_hp_fstab_mount(pagesize):
    log("Remove {} mountpoint from fstab".format(pagesize))
    mnt_point = '/dev/hugepages{}'.format(pagesize)
    lfstab = fstab.Fstab()
    fstab_entry = lfstab.get_entry_by_attr('mountpoint', mnt_point)
    if fstab_entry:
        umount(mnt_point)
        lfstab.remove_entry(fstab_entry)


def _add_hp_fstab_mount(pagesize, mount=True):
    log("Add {} mountpoint from fstab".format(pagesize))
    mnt_point = '/dev/hugepages{}'.format(pagesize)
    mkdir(mnt_point, owner='root', group='root', perms=0o755)
    lfstab = fstab.Fstab()
    fstab_entry = lfstab.get_entry_by_attr('mountpoint', mnt_point)
    if fstab_entry:
        lfstab.remove_entry(fstab_entry)
    # use different device name for 1G and 2M.
    # this name actually is not used by the system
    # but add_antry filter by device name.
    device = 'hugetlbfs{}'.format(pagesize)
    entry = lfstab.Entry(device, mnt_point, 'hugetlbfs',
                         'pagesize={}'.format(pagesize), 0, 0)
    lfstab.add_entry(entry)
    if mount:
        fstab_mount(mnt_point)


def _remove_file(f):
    try:
        log("Remove {}".format(f))
        os.remove(f)
    except FileNotFoundError:
        return False
    return True


def prepare_hugepages_kernel_mode():
    p_1g = _get_hp_options("kernel-hugepages-1g")
    p_2m = _get_hp_options("kernel-hugepages-2m")

    if p_1g == 0 and p_2m == 0:
        log("No hugepages set for kernel mode. Skip configuring.")
        return

    sysctl_file = '/etc/sysctl.d/10-contrail-hugepage.conf'
    # use prefix 60- because of
    # https://bugs.launchpad.net/curtin/+bug/1527664
    cfg_file = '/etc/default/grub.d/60-contrail-agent.cfg'

    if p_1g == 0:
        _del_hp_fstab_mount('1G')
        if _remove_file(cfg_file):
            log("grub config file is present but 1G disabled - update grub")
            check_call(["update-grub"])
        log("Allocate {} x {} hugepages via sysctl".format(p_2m, '2MB'))
        sysctl.create(yaml.dump({'vm.nr_hugepages': p_2m}), sysctl_file)
        _add_hp_fstab_mount('2M')
        return

    # remove sysctl file as hugepages be allocated via kernel args
    _remove_file(sysctl_file)

    # 1gb avalable only on boot time, so change kernel boot options
    boot_opts = "default_hugepagesz=1G hugepagesz=1G hugepages={}".format(p_1g)
    _add_hp_fstab_mount('1G', mount=False)
    if p_2m != 0:
        boot_opts += " hugepagesz=2M hugepages={}".format(p_2m)
        _add_hp_fstab_mount('2M', mount=False)
    else:
        _del_hp_fstab_mount('2M')
    log("Update grub config for hugepages: {}".format(boot_opts))
    mkdir('/etc/default/grub.d', perms=0o744)
    new_content = 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT {}"'.format(boot_opts)
    try:
        old_content = check_output(['cat', cfg_file]).decode('UTF-8')
        log("Old kernel boot paramters: {}".format(old_content))
        if old_content == new_content:
            log("Kernel boot parameters are not changed")
            return
    except Exception:
        pass
    log("New kernel boot paramters: {}".format(new_content))
    write_file(cfg_file, new_content, perms=0o644)
    check_call(["update-grub"])


def get_vhost_ip():
    try:
        addr = netifaces.ifaddresses("vhost0")
        if netifaces.AF_INET in addr and len(addr[netifaces.AF_INET]) > 0:
            return addr[netifaces.AF_INET][0]["addr"]
    except ValueError:
        pass

    iface = config.get("physical-interface")
    if not iface:
        iface = _get_default_gateway_iface()
    addr = netifaces.ifaddresses(iface)
    if netifaces.AF_INET in addr and len(addr[netifaces.AF_INET]) > 0:
        return addr[netifaces.AF_INET][0]["addr"]

    return None


def tsn_ctx():
    result = dict()
    result["csn_mode"] = config.get("csn-mode")
    if not result["csn_mode"]:
        return result

    tsn_ip_list = []
    for rid in relation_ids("agent-cluster"):
        for unit in related_units(rid):
            ip = relation_get("vhost-address", unit, rid)
            if ip:
                tsn_ip_list.append(ip)
    # add own ip address
    tsn_ip_list.append(get_vhost_ip())

    result["tsn_nodes"] = tsn_ip_list
    return result


def update_nrpe_config():
    plugins_dir = '/usr/local/lib/nagios/plugins'
    nrpe_compat = nrpe.NRPE(primary=False)
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
    "contrail-controller",
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


def ziu_stage_5(ziu_stage, trigger):
    # wait for upgrade action and then signal
    if trigger == 'upgrade':
        ctx = get_context()
        _run_services(ctx)
        signal_ziu("ziu_done", ziu_stage)


def ziu_stage_6(ziu_stage, trigger):
    # finish
    signal_ziu("ziu", None)
    signal_ziu("ziu_done", None)


stages = {
    0: ziu_stage_0,
    1: ziu_stage_noop,
    2: ziu_stage_noop,
    3: ziu_stage_noop,
    4: ziu_stage_noop,
    5: ziu_stage_5,
    6: ziu_stage_6,
}
