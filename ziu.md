# ZIU procedure for Juju deployments with OpenStack

## Description

This procedure assumes that you have working cluster with control plane, compute nodes and OpenStack controllers. Please do full backup before procedure.

## Procedure

### Start:

`juju run-action contrail-controller/leader upgrade-ziu`

All services of control plane (controller, analytics, analyticsdb) go to the maintenance mode.

### Configurate services with new image-tag:

```bash
juju config contrail-analytics image-tag=master-latest
juju config contrail-analyticsdb image-tag=master-latest
juju config contrail-agent image-tag=master-latest
juju config contrail-openstack image-tag=master-latest
juju config contrail-controller image-tag=master-latest
```

The upgrade process starts.

It automatically passes 6 stages.

    Stage 0. Pull new images.
    Stage 1. Stops config containers.
    Stage 2. Start config containers with new tag.
    Stage 3. Restart control containers one-by-one.
    Stage 4. Restart database containers one-by-one.
    Stage 5. Restart contrail-agent container.

You can track the process through `juju status`.

```bash
Unit                       Workload     Agent      Machine  Public address  Ports                     Message
contrail-analytics/0*      maintenance  idle       3        10.0.12.20      8081/tcp                  ziu is in progress - stage/done = 4/4
contrail-analytics/1       maintenance  idle       4        10.0.12.21      8081/tcp                  ziu is in progress - stage/done = 4/4
contrail-analytics/2       maintenance  idle       5        10.0.12.22      8081/tcp                  ziu is in progress - stage/done = 4/4
contrail-analyticsdb/0*    maintenance  idle       3        10.0.12.20                                ziu is in progress - stage/done = 4/4
contrail-analyticsdb/1     maintenance  idle       4        10.0.12.21                                ziu is in progress - stage/done = 4/3
contrail-analyticsdb/2     maintenance  idle       5        10.0.12.22                                ziu is in progress - stage/done = 4/3
contrail-controller/0*     maintenance  idle       3        10.0.12.20                                ziu is in progress - stage/done = 4/4
  ntp/3                    active       idle                10.0.12.20      123/udp                   chrony: Ready
contrail-controller/1      maintenance  executing  4        10.0.12.21                                ziu is in progress - stage/done = 4/3
  ntp/2                    active       idle                10.0.12.21      123/udp                   chrony: Ready
contrail-controller/2      maintenance  idle       5        10.0.12.22                                ziu is in progress - stage/done = 4/3
  ntp/4                    active       idle                10.0.12.22      123/udp                   chrony: Ready
contrail-keystone-auth/0*  active       idle       3/lxd/0  10.0.12.121                               Unit is ready
```

wait for all charms are in stage 5/5 about 40 minutes.

### Upgrade computes

`juju run-action contrail-agent/0 upgrade`

Wait for success about 5 minutes - please check output of action and juju status.

### Reboot computes

vRouter upgrade will require a reboot of the upgraded node in two cases: kernel version changed or not enough contiguous memory after reload of vrouter kmod available. Reboots & workload migrations are to be planned by the user and depends on the particular user environment and its requirements to workloads.
In general the rule for reboot is :
- new kernel 		=> reboot required
- new kernel module 	=> reboot might be needed (lack of contiguous memory)
- new dpdk pmd 	=> no reboot

Reboot the compute nodes manually.

`sudo reboot`

### The end

Now you should have fully worked deployment with new control, config, database and data planes.
