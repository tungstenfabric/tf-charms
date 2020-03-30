Overview
--------

Contrail Command is the GUI for Contrail Cloud and Contrail Enterprise Multicloud solutions. It represents the single management touchpoint for the fabric underlay, the overlay networks and virtual endpoints, and the AppFormix performance and resource monitoring application for cloud services.

Contrail Command also simplifies the configuration of OpenStack clusters and the integration of Contrail within those clusters. By providing a workflow to facilitate integration with orchestrators, initially providing support for OpenStack Kolla, Contrail Command makes integration a straightforward task.

In a Canonical OpenStack environment the operator will deploy the Command UI to manage an existing OpenStack cluster. The operator will use a JuJu Charm to deploy the Command containers, and import the existing cluster.
Only for Contrail 5.0 for now.
Juju 2.0 is required.

Usage
-----

Once ready deploy, relate and run action as follows:

1. Deploy.

    juju deploy contrail-command --config docker-registry='10.160.12.173/contrail-nightly' --config image-tag=master-latest

2. Relate

        juju add-relation contrail-command contrail-controller

3. To import cluster run action:

    We advise you to create configure file:

        $ cat config.yaml
        juju-controller: <juju-controller-ip>
        juju-controller-password: <password>
        juju-ca-cert: |
            <juju-CA-certificate>
        juju-model-id: <juju-model-id>
        juju-controller-user: <juju-controller-user> # (optionally, 'admin' by default)

    Fill it with

    - juju-controller-ip: IP of JuJu controller. You can get it from `juju show-controller` command.

            jenkins@contrail-ci:~$ juju show-controller
            jc5-cloud:
                details:
                    ...(skipped)...
                    api-endpoints: [10.0.12.99:17070]
                    ...(skipped)...

    - juju-ca-cert-path: base64-encoded SSL CA to Juju controller. CA cert may be found by command `juju show-controller` (ca-cert)

            $ juju show-controller
            jc5-cloud:
                details:
                    ...(skipped)...
                    ca-cert: |
                    -----BEGIN CERTIFICATE-----
                    MIIErTCCAxWgAwIBAgIVAJxfIwgMrGF/
                    ................................+C1sDvj5qCGSpQGT7NPmDtAlrK
                    eQ==
                    -----END CERTIFICATE-----
                    ...(skipped)...

        Don't forget to encode it to base64

            $ cat cert.pem | base64 > "cert.pem.b64"

    - juju-model-id: ID of JuJu model. You can get it from `juju show-controller` command.

            jc5-cloud:
                ...(skipped)...
                models:
                    default:
                    model-uuid: 4a62e0b0-bcfe-4b35-8da7-48e55f439237
                ...(skipped)...

    - password: password for juju controller access. You should set password for Juju by `juju change-user-password` command.

    - juju-controller-user: user for juju controller access. User 'admin' is used by default.

    Run import-cluster:

        juju run-action contrail-command/0 import-cluster --params config.yaml

    You can check the results with `juju show-action-status <action id>`

        actions:
        - action: import-cluster
        completed at: "2020-04-03 12:49:55"
        id: "60"
        status: completed
        unit: contrail-command/19

    status should be **completed**, then you can check `juju show-action-output <action id> | grep result`

        results:
            result: Success
