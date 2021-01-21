#!/usr/bin/env python3
import sys

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_id,
    relation_get,
    relation_ids,
    related_units,
    status_set,
    relation_set,
)

import contrail_openstack_ironic_utils as utils
import common_utils
import docker_utils


hooks = Hooks()
config = config()


# TODO:
# - check SSL for RabbitMQ


@hooks.hook("install.real")
def install():
    status_set('maintenance', 'Installing...')

    docker_utils.install()
    status_set("blocked", "Missing relation to contrail-controller")


@hooks.hook("config-changed")
def config_changed():
    docker_utils.config_changed()

    if config.changed("rabbit-user") or config.changed("rabbit-vhost"):
        _notify_amqp()

    utils.pull_images()
    utils.update_charm_status()


def _notify_controller(rid=None):
    rids = [rid] if rid else relation_ids("contrail-controller")
    if not rids:
        return

    settings = {'unit-type': 'openstack-ironic'}
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("contrail-controller-relation-joined")
def contrail_controller_joined():
    _notify_controller(rid=relation_id())


@hooks.hook("contrail-controller-relation-changed")
def contrail_controller_changed():
    data = relation_get()

    _update_config(data, "analytics_servers", "analytics-server")
    _update_config(data, "auth_info", "auth-info")
    _update_config(data, "orchestrator_info", "orchestrator-info")
    config.save()

    utils.update_charm_status()


@hooks.hook("contrail-controller-relation-departed")
def contrail_cotroller_departed():
    units = [unit for rid in relation_ids("contrail-controller")
             for unit in related_units(rid)]
    if units:
        return

    keys = ["auth_info", "orchestrator_info", "analytics-server"]
    for key in keys:
        config.pop(key, None)
    utils.update_charm_status()
    status_set("blocked", "Missing relation to contrail-controller")


def _notify_amqp(rid=None):
    rids = [rid] if rid else relation_ids("amqp")
    if not rids:
        return

    settings = {
        'username': config.get("rabbit-user"),
        'vhost': config.get("rabbit-vhost"),
    }
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("amqp-relation-joined")
def amqp_joined():
    _notify_amqp(rid=relation_id())


@hooks.hook("amqp-relation-changed")
def amqp_changed():
    data = relation_get()

    _update_config(data, "rabbit-hostname", "hostname")
    _update_config(data, "rabbit-password", "password")
    config.save()

    utils.update_charm_status()


@hooks.hook("amqp-relation-departed")
def amqp_departed():
    config.pop("rabbit-hostname", None)
    config.pop("rabbit-password", None)
    config.save()

    utils.update_charm_status()


@hooks.hook("update-status")
def update_status():
    # and update self
    utils.update_charm_status()


def _update_config(data, key, data_key):
    if data_key in data:
        changed = config.get(key) != data[data_key]
        config[key] = data[data_key]
    else:
        changed = key in config
        config.pop(key, None)
    return changed


def _update_tls(rid=None):
    rids = [rid] if rid else relation_ids("tls-certificates")
    if not rids:
        return

    config['tls_present'] = True
    settings = common_utils.get_tls_settings(common_utils.get_ip())
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook('tls-certificates-relation-joined')
def tls_certificates_relation_joined():
    _update_tls(rid=relation_id())


@hooks.hook('tls-certificates-relation-changed')
def tls_certificates_relation_changed():
    # it can be fired several times without server's cert
    if common_utils.tls_changed(utils.MODULE, relation_get()):
        utils.update_charm_status()


@hooks.hook('tls-certificates-relation-departed')
def tls_certificates_relation_departed():
    config['tls_present'] = False
    common_utils.tls_changed(utils.MODULE, None)
    utils.update_charm_status()


@hooks.hook("upgrade-charm")
def upgrade_charm():
    # to update config flags and certs params if any was changed
    _update_tls()

    utils.update_charm_status()


@hooks.hook("stop")
def stop():
    utils.stop_openstack_ironic()
    utils.remove_created_files()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
