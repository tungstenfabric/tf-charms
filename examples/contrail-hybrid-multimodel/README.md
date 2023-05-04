Sample bundle to deploy Contrail with K8s and Openstack with authorization k8s pods on keystone on multi-model setup.


## Deployment of multi-model.

0. The initial model is creating during `juju bootstrap`. The name may be specified with `--add-model` parameter.
Let the initial model be called 'openstack'.

1. Deploy Contrail-Openstack bundle for openstack model.
```bash
juju -m openstack deploy ./openstack_bundle.yaml`
```

2. Add 'kubernetes' model for kubernetes.
```bash
juju add-model k8s
```

3. Deploy k8s bundle
```bash
juju -m k8s deploy ./k8s_bundle.yaml
```

4. Add offer for contrail-controller and keystone (if you are using keystone authorization for k8s).
```bash
juju -m k8s offer openstack.tf-controller:contrail-controller
juju -m k8s offer openstack.keystone:identity-credentials
```

5. Add relations to contrail-openstack
```bash
juju -m k8s add-relation tf-kubernetes-master openstack.tf-controller
juju -m k8s add-relation tf-agent openstack.tf-controller
juju -m k8s add-relation kubernetes-master openstack.keystone
```

## ZIU procedure for multi-model

WARNING: This document describes only the nuances for the ziu procedure. The main procedure is described in [ziu.md](../../ziu.md) document

### Start:

```bash
juju run-action contrail-controller/leader upgrade-ziu
```

Wait untill all services of control plane (controller, analytics, analyticsdb) go to the maintenance mode.

### Configure services on **both models** with new image-tag:

```bash
juju switch openstack
juju config contrail-analytics image-tag=<new tag>
juju config contrail-analyticsdb image-tag=<new tag>
juju config contrail-agent image-tag=<new tag>
juju config contrail-openstack image-tag=<new tag>
juju config contrail-controller image-tag=<new tag>

juju switch k8s
juju config contrail-kubernetes-master image-tag=<new tag>
juju config contrail-kubernetes-node image-tag=<new tag>
juju config contrail-agent image-tag=<new tag>
```

wait for all charms in **both models** are in stage 5/5 about 40 minutes.

### Upgrade computes

```bash
juju switch openstack
juju run-action contrail-agent/0 upgrade

juju switch k8s
juju run-action contrail-agent/0 upgrade
```

Wait for success about 5 minutes.
