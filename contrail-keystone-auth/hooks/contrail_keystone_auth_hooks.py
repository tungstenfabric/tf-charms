#!/usr/bin/env python3

import base64
import json
import sys

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_get,
    relation_ids,
    relation_set,
    relation_id,
    related_units,
    status_set,
    ERROR,
)

hooks = Hooks()
config = config()


def _decode_cert(key):
    val = config.get(key)
    if not val:
        return None
    try:
        return base64.b64decode(val).decode()
    except Exception as e:
        log("Couldn't decode certificate from config['{}']: {}".format(
            key, str(e)), level=ERROR)
    return None


def _match_region(region, service_region):
    """Match configured region against keystone service_region value obtained
    via identity-admin relation from keystone. If keystone is configured
    with multiple regions then value of service_region is a space-separated
    string of keystone region names. If the region can be found
    among regions in the service_region then return the it.
    If no match is found between non-empty configured region and the service_region
    then exception is raised - user has to choose correct value.
    """
    service_regions = service_region.split()
    if not region:
        if len(service_regions) > 1:
            log("Region is not set in config. Keystone has multiple values {}"
                "".format(service_region), level=ERROR)
            raise("Keystone provided more than 1 region. Please configure region in config.")
        # otherwise return original string from keystone even if it's empty
        return service_region

    if region not in service_regions:
        log("Region in config({}) is not equal to keystone provided({})"
            "".format(region, service_region), level=ERROR)
        raise("Configured region is not present in keystone. Please change it or unset.")

    return region


def update_relations(rid=None):
    rids = [rid] if rid else relation_ids("contrail-auth")
    if not rids:
        return

    auth_info = config.get("auth_info")
    if auth_info:
        data = json.loads(auth_info)
        data["keystone_ssl_ca"] = _decode_cert("ssl_ca")
        data["keystone_region"] = _match_region(config.get("region"), config.get("service_region"))
        auth_info = json.dumps(data)
    settings = {
        "auth-info": auth_info
    }
    for rid in rids:
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook("config-changed")
def config_changed():
    _decode_cert("ssl_ca")
    update_relations()
    update_status()


@hooks.hook("contrail-auth-relation-joined")
def contrail_auth_joined():
    update_relations(rid=relation_id())
    update_status()


@hooks.hook("identity-admin-relation-changed")
def identity_admin_changed():
    ip = relation_get("service_hostname")
    if ip:
        api_version = int(relation_get("api_version"))
        api_suffix = 'v2.0' if api_version == 2 else 'v3'
        api_tokens = 'v2.0/tokens' if api_version == 2 else 'v3/auth/tokens'
        auth_info = {
            "keystone_protocol": relation_get("service_protocol"),
            "keystone_ip": ip,
            "keystone_public_port": relation_get("service_port"),
            "keystone_admin_user": relation_get("service_username"),
            "keystone_admin_password": relation_get("service_password"),
            "keystone_admin_tenant": relation_get("service_tenant_name"),
            "keystone_api_version": api_version,
            "keystone_api_suffix": api_suffix,
            "keystone_api_tokens": api_tokens,
            # next three field are only for api_version = 3
            "keystone_user_domain_name":
                relation_get("service_user_domain_name"),
            "keystone_project_domain_name":
                relation_get("service_project_domain_name"),
            "keystone_project_name": relation_get("service_project_name"),
        }
        auth_info = json.dumps(auth_info)
        config["auth_info"] = auth_info
        # save list of regions in case of multi-region setup
        config["service_region"] = relation_get("service_region")
    else:
        config.pop("auth_info", None)
        config.pop("service_region")

    update_relations()
    update_status()


@hooks.hook("identity-admin-relation-departed")
def identity_admin_departed():
    count = 0
    for rid in relation_ids("identity-admin"):
        count += len(related_units(rid))
    if count > 0:
        return
    config.pop("auth_info", None)
    config.pop("service_region")

    update_relations()
    update_status()


@hooks.hook("update-status")
def update_status():
    auth_info = config.get("auth_info")
    if not auth_info:
        status_set('blocked', 'Missing relations: identity')
    else:
        status_set("active", "Unit is ready")


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))


if __name__ == "__main__":
    main()
