# Sample overlay bundle to deploy Ironic with Contrail+OpenStack

This readme was prepared for Ubuntu 18.04. To deploy it in Ubuntu 20.04 please use innodb instead of mysql/percona.
Prepare Juju setup with openstack Train and ironic overlay bundle:

```bash
juju deploy --overlay=./ironic-bundle.yaml ./bundle.yaml
```

or you can add ironic in a same way after deployment of main bundle:

```bash
juju deploy --overlay=./ironic-bundle.yaml --map-machines=existing ./bundle.yaml
```

Please note - if you have network bindings in main bundle file then you have to replicate it to octavia’s bundle.

To deploy this overlay you need to have ceph in your main bundle. Please refer to Canonical's docs how to deploy it.
This overlay add ironic-api, ironic-conductor, nova-compute in ironic mode and contrail-agent in CSN mode.
For detailed information about ironic please check its page <https://jaas.ai/u/openstack-charmers/ironic-conductor>
