# ISSU procedure for Juju deployments with OpenStack


## Description

This procedure assumes that you have working cluster with control plane, compute nodes and OpenStack controllers. With ISSU procedure you have to install new control plane of Contrail services and switch contrail-agents to this new control plane one by one. And at the end switch OpenStack plugins and then remove old control plane. Please note that only controller databases are migrated. Analytics database will not be migrated. Please do full backup before procedure.

## Procedure

### setup new control plane:

Choose different names and machines for applications (contrail-controller, contrail-analyticsdb, contrail-analytics) to deploy and then deploy them manually or from the bundle. Example:

```bash
juju deploy ./tf-charms/contrail-controller contrail-controller2 --to 4 --config log-level=SYS_DEBUG --config auth-mode=cloud-admin --config cassandra-minimum-diskgb="4" --config cassandra-jvm-extra-opts="-Xms1g -Xmx2g" --config data-network=ens4 --config docker-registry=opencontrailnightly --config image-tag=master-latest --config docker-registry-insecure=true
juju deploy ./tf-charms/contrail-analytics contrail-analytics2 --to 4 --config log-level=SYS_DEBUG --config docker-registry=opencontrailnightly --config image-tag=master-latest --config docker-registry-insecure=true
juju deploy ./tf-charms/contrail-analyticsdb contrail-analyticsdb2 --to 4 --config log-level=SYS_DEBUG --config cassandra-minimum-diskgb="4" --config cassandra-jvm-extra-opts="-Xms1g -Xmx2g" --config docker-registry=opencontrailnightly --config image-tag=master-latest --config docker-registry-insecure=true
juju add-relation "contrail-controller2" "ntp"
juju add-relation "contrail-controller2" "contrail-keystone-auth"
juju add-relation "contrail-controller2" "contrail-analytics2"
juju add-relation "contrail-controller2" "contrail-analyticsdb2"
juju add-relation "contrail-analytics2" "contrail-analyticsdb2"
```

Relate new control plane with old one to inform computes about maintenance mode and IP-s of new control plane:

`juju add-relation contrail-controller:contrail-controller contrail-controller2:contrail-issu`

wait for all charms are active about 10 minutes.

### Sync new control plane with old one

Run pre-sync and run-sync on new controller. Configuration file should be prepared by charms and placed into /etc/contrail/contrail-issu.conf. Please run below commands from any new controller node. Please use the same image tag as you configured for deployment of new control plane:

```bash
sudo docker run --rm -it --network host -v /etc/contrail/contrail-issu.conf:/etc/contrail/contrail-issu.conf --entrypoint /bin/bash -v /var/log/contrail:/var/log/contrail -v /root/.ssh:/root/.ssh opencontrailnightly/contrail-controller-config-api:master-latest -c "/usr/bin/contrail-issu-pre-sync -c /etc/contrail/contrail-issu.conf"
sudo docker run --rm --detach -it --network host -v /etc/contrail/contrail-issu.conf:/etc/contrail/contrail-issu.conf --entrypoint /bin/bash -v /var/log/contrail:/var/log/contrail -v /root/.ssh:/root/.ssh --name issu-run-sync opencontrailnightly/contrail-controller-config-api:master-latest -c "/usr/bin/contrail-issu-run-sync -c /etc/contrail/contrail-issu.conf"
```

Then two control containers have to be manually restarted on all nodes of new control plane:

`sudo restart control_control_1 control_provisioner_1`

### Upgrade computes

Contrail-agents should be upgraded on by one without workload to prevent downtime for workload. To achieve this you have to migrate workload with live-migration feature from upgraded compute.
Please set new image-tag for contrail-agent. If you need to migrate from R5.0 then you may want to set hostname-use-fqdn to false for contrail-agent charm. R5.0 used short names for services and nodes in the cluster are registered with short names, therefore new version of contrail-agent may register node with different name and break connectivity. Please refer to config options of contrail-agent for additional explanation.

Choose compute unit and migrate it:

`juju run-action contrail-agent/0 upgrade`

Wait for success about 5 minutes - please check output of action and juju status.

### Finish migration

Please stop run sync container on the node where you run it:

`sudo docker rm -f issu-run-sync`

And run post sync there:

```bash
sudo docker run --rm -it --network host -v /var/log/contrail:/var/log/contrail -v /etc/contrail/contrail-issu.conf:/etc/contrail/contrail-issu.conf --entrypoint /bin/bash -v /var/log/contrail:/var/log/contrail -v /root/.ssh:/root/.ssh opencontrailnightly/contrail-controller-config-api:master-latest -c "/usr/bin/contrail-issu-post-sync -c /etc/contrail/contrail-issu.conf"
sudo docker run --rm -it --network host -v /var/log/contrail:/var/log/contrail -v /etc/contrail/contrail-issu.conf:/etc/contrail/contrail-issu.conf --entrypoint /bin/bash -v /var/log/contrail:/var/log/contrail -v /root/.ssh:/root/.ssh opencontrailnightly/contrail-controller-config-api:master-latest -c "/usr/bin/contrail-issu-zk-sync -c /etc/contrail/contrail-issu.conf"
```

Set new image-tag for contrail-openstack charm:

`juju config contrail-openstack image-tag=master-latest`

Then you can finish operation with switching relations to new cluster, removing relation between new and old control plane, removing old control plane:

```bash
juju remove-relation contrail-controller contrail-agent
juju remove-relation contrail-controller contrail-openstack
juju add-relation contrail-controller2 contrail-agent
juju add-relation contrail-controller2 contrail-openstack
juju remove-relation contrail-controller:contrail-controller contrail-controller2:contrail-issu
juju remove-application contrail-controller
juju remove-application contrail-analytics
juju remove-application contrail-analyticsdb
```

Additionaly you have to remove old control plane nodes from Contrail itself and add new. On the same node where you run sync operations - create new config for this (issu.conf). Please use real values for all nodes (*_host_info) - IP-s, names; real values for credentials; and IP of any config API server:

```
[DEFAULTS]
db_host_info={"10.0.12.27": "jc5-cont-7"}
config_host_info={"10.0.12.27": "jc5-cont-7"}
analytics_host_info={"10.0.12.27": "jc5-cont-7"}
control_host_info={"10.0.12.27": "jc5-cont-7"}
admin_password = password
admin_tenant_name = admin
admin_user = admin
api_server_ip=10.0.12.27
api_server_port=8082
```

run script:

```bash
sudo docker cp issu.conf configapi_api_1:issu.conf`
sudo docker exec -it configapi_api_1 python /opt/contrail/utils/provision_issu.py -c issu.conf
```

### The end

Now you should have fully worked deployment with new control plane and migrated contrail-agent's.
