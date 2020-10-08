#!/usr/bin/env python3

import json
import sys
import uuid
import yaml

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    related_units,
    relation_get,
    relation_ids,
    relation_set,
    status_set,
    leader_get,
    leader_set,
    is_leader,
    unit_private_ip,
)

import common_utils
import contrail_openstack_utils as utils
import docker_utils


hooks = Hooks()
config = config()


@hooks.hook("install.real")
def install():
    status_set('maintenance', 'Installing...')

    docker_utils.install()
    status_set("blocked", "Missing relation to contrail-controller")


@hooks.hook("config-changed")
def config_changed():
    notify_nova = False
    changed = docker_utils.config_changed()
    if changed or config.changed("image-tag"):
        notify_nova = True
        _notify_neutron()
        _notify_heat()

    if is_leader():
        _configure_metadata_shared_secret()
        notify_nova = True

    _notify_controller()

    if notify_nova:
        _notify_nova()


@hooks.hook("leader-elected")
def leader_elected():
    utils.update_service_ips()
    _configure_metadata_shared_secret()
    _notify_nova()
    _notify_controller()


@hooks.hook("leader-settings-changed")
def leader_settings_changed():
    _notify_nova()


@hooks.hook("contrail-controller-relation-joined")
def contrail_controller_joined(rel_id=None):
    settings = {
        'unit-type': 'openstack',
        'use-internal-endpoints': config.get('use-internal-endpoints'),
    }
    settings.update(_get_orchestrator_info())
    relation_set(relation_id=rel_id, relation_settings=settings)


def _rebuild_config_from_controller_relation():
    items = dict()

    def _update_item(data, key, data_key):
        val = data.get(data_key)
        if val is not None:
            items[key] = val

    ip = unit_private_ip()
    units = [(rid, unit) for rid in relation_ids("contrail-controller")
             for unit in related_units(rid)]
    # add relation info as last item to override outdated data
    units.append((None, None))
    for rid, unit in units:
        data = relation_get(attribute=None, unit=unit, rid=rid)
        if data is None:
            if "dpdk" not in items:
                items["dpdk"] = False
            continue

        _update_item(data, "auth_info", "auth-info")
        _update_item(data, "auth_mode", "auth-mode")
        _update_item(data, "controller_ips", "controller_ips")

        info = data.get("agents-info")
        if not info:
            items["dpdk"] = False
        else:
            value = json.loads(info).get(ip, False)
            if not isinstance(value, bool):
                value = yaml.load(value)
            items["dpdk"] = value

    if not items.get("dpdk"):
        log("DPDK for current host is False. agents-info is not provided.")
    else:
        log("DPDK for host {ip} is {dpdk}".format(ip=ip, dpdk=value))

    for key in ["auth_info", "auth_mode", "controller_ips", "dpdk"]:
        if key in items:
            config[key] = items[key]
        else:
            config.pop(key, None)


def _update_status():
    if "controller_ips" not in config:
        status_set("blocked", "Missing relation to contrail-controller (controller_ips is empty or absent in relation)")
    else:
        status_set("active", "Unit is ready")


@hooks.hook("contrail-controller-relation-changed")
def contrail_controller_changed():
    _rebuild_config_from_controller_relation()
    config.save()
    utils.write_configs()
    _update_status()

    # apply information to base charms
    _notify_nova()
    _notify_neutron()
    _notify_heat()

    # auth_info can affect endpoints
    if is_leader() and utils.update_service_ips():
        _notify_controller()


@hooks.hook("contrail-controller-relation-departed")
def contrail_cotroller_departed():
    _rebuild_config_from_controller_relation()
    config.save()
    utils.write_configs()
    _update_status()


def _configure_metadata_shared_secret():
    secret = leader_get("metadata-shared-secret")
    if config["enable-metadata-server"] and not secret:
        secret = str(uuid.uuid4())
    elif not config["enable-metadata-server"] and secret:
        secret = None
    else:
        return

    leader_set(settings={"metadata-shared-secret": secret})


def _notify_controller():
    for rid in relation_ids("contrail-controller"):
        if related_units(rid):
            contrail_controller_joined(rid)


def _notify_nova():
    for rid in relation_ids("nova-compute"):
        if related_units(rid):
            nova_compute_joined(rid)


def _notify_neutron():
    for rid in relation_ids("neutron-api"):
        if related_units(rid):
            neutron_api_joined(rid)


def _notify_heat():
    for rid in relation_ids("heat-plugin"):
        if related_units(rid):
            heat_plugin_joined(rid)


def _get_orchestrator_info():
    info = {"cloud_orchestrator": "openstack"}
    if config["enable-metadata-server"]:
        info["metadata_shared_secret"] = leader_get("metadata-shared-secret")

    def _add_to_info(key):
        value = leader_get(key)
        if value:
            info[key] = value

    _add_to_info("compute_service_ip")
    _add_to_info("image_service_ip")
    _add_to_info("network_service_ip")
    return {"orchestrator-info": json.dumps(info)}


@hooks.hook("heat-plugin-relation-joined")
def heat_plugin_joined(rel_id=None):
    utils.deploy_openstack_code("contrail-openstack-heat-init", "heat")

    plugin_path = utils.get_component_sys_paths("heat") + "/vnc_api/gen/heat/resources"
    plugin_dirs = config.get("heat-plugin-dirs")
    if plugin_path not in plugin_dirs:
        plugin_dirs += ',' + plugin_path
    ctx = utils.get_context()
    sections = {
        "clients_contrail": [
            ("user", ctx.get("keystone_admin_user")),
            ("password", ctx.get("keystone_admin_password")),
            ("tenant", ctx.get("keystone_admin_tenant")),
            ("api_server", " ".join(ctx.get("api_servers"))),
            ("auth_host_ip", ctx.get("keystone_ip")),
            ("use_ssl", ctx.get("ssl_enabled")),
        ]
    }

    if ctx.get("ssl_enabled") and "ca_cert_data" in ctx:
        ca_file_path = "/etc/heat/contrail-ca-cert.pem"
        common_utils.save_file(ca_file_path, ctx["ca_cert_data"], perms=0o644)
        sections["clients_contrail"].append(("cafile", ca_file_path))

    conf = {
        "heat": {
            "/etc/heat/heat.conf": {
                "sections": sections
            }
        }
    }
    settings = {
        "plugin-dirs": plugin_dirs,
        "subordinate_configuration": json.dumps(conf)
    }
    relation_set(relation_id=rel_id, relation_settings=settings)


@hooks.hook("neutron-api-relation-joined")
def neutron_api_joined(rel_id=None):
    version = utils.get_openstack_version_codename('neutron')
    utils.deploy_openstack_code(
        "contrail-openstack-neutron-init", "neutron",
        {"OPENSTACK_VERSION": utils.PACKAGE_CODENAMES['neutron'][version]})

    # create plugin config
    contrail_version = common_utils.get_contrail_version()
    plugin_path = utils.get_component_sys_paths("neutron")
    base = "neutron_plugin_contrail.plugins.opencontrail"
    plugin = base + ".contrail_plugin.NeutronPluginContrailCoreV2"
    # pass just separator to prevent setting of default list
    service_plugins = "contrail-timestamp,"
    if contrail_version >= 1909:
        service_plugins += "contrail-trunk,"
    if contrail_version >= 2005 and version > 12:
        service_plugins += "contrail-tags,"
    if version < 15:
        service_plugins += base + ".loadbalancer.v2.plugin.LoadBalancerPluginV2,"
    contrail_plugin_extension = plugin_path + "/neutron_plugin_contrail/extensions"
    neutron_lbaas_extensions = plugin_path + "/neutron_lbaas/extensions"
    extensions = [
        contrail_plugin_extension,
        neutron_lbaas_extensions
    ]
    conf = {
        "neutron-api": {
            "/etc/neutron/neutron.conf": {
                "sections": {
                    "DEFAULT": [
                        ("api_extensions_path", ":".join(extensions))
                    ]
                }
            }
        }
    }
    settings = {
        "neutron-plugin": "contrail",
        "core-plugin": plugin,
        "neutron-plugin-config":
            "/etc/neutron/plugins/opencontrail/ContrailPlugin.ini",
        "service-plugins": service_plugins,
        "quota-driver": base + ".quota.driver.QuotaDriver",
        "subordinate_configuration": json.dumps(conf),
    }
    auth_mode = config.get("auth_mode", "cloud-admin")
    if auth_mode == "rbac":
        settings["extra_middleware"] = [{
            "name": "user_token",
            "type": "filter",
            "config": {
                "paste.filter_factory":
                    base + ".neutron_middleware:token_factory"
            }
        }]
    relation_set(relation_id=rel_id, relation_settings=settings)

    # if this hook raised after contrail-controller we need
    # to overwrite default config file after installation
    utils.write_configs()


@hooks.hook("nova-compute-relation-joined")
def nova_compute_joined(rel_id=None):
    utils.deploy_openstack_code("contrail-openstack-compute-init", "nova")

    utils.nova_patch()

    # create plugin config
    sections = {
        "DEFAULT": [
            ("firewall_driver", "nova.virt.firewall.NoopFirewallDriver")
        ]
    }
    if config.get("dpdk", False):
        sections["CONTRAIL"] = [("use_userspace_vhost", "True")]
        sections["libvirt"] = [("use_huge_pages", "True")]
    conf = {
        "nova-compute": {
            "/etc/nova/nova.conf": {
                "sections": sections
            }
        }
    }
    settings = {
        "metadata-shared-secret": leader_get("metadata-shared-secret"),
        "subordinate_configuration": json.dumps(conf)}
    relation_set(relation_id=rel_id, relation_settings=settings)


@hooks.hook("update-status")
def update_status():
    # TODO: try to deploy openstack code again if it was not done
    # update_service_ips can be called only on leader. notify controller only if something was updated
    if is_leader() and utils.update_service_ips():
        _notify_controller()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    _rebuild_config_from_controller_relation()
    config.save()
    utils.write_configs()
    _update_status()

    if is_leader():
        utils.update_service_ips()
    # apply information to base charms
    _notify_nova()
    _notify_neutron()
    _notify_heat()
    _notify_controller()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
