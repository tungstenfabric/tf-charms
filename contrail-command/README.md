Overview
--------

Contrail Command is the GUI for Contrail Cloud and Contrail Enterprise Multicloud solutions. It represents the single management touchpoint for the fabric underlay, the overlay networks and virtual endpoints, and the AppFormix performance and resource monitoring application for cloud services.

Contrail Command also simplifies the configuration of OpenStack clusters and the integration of Contrail within those clusters. By providing a workflow to facilitate integration with orchestrators, initially providing support for OpenStack Kolla, Contrail Command makes integration a straightforward task.

In a Canonical OpenStack environment the operator will deploy the Command UI to manage an existing OpenStack cluster. The operator will use a JuJu Charm to deploy the Command containers, and import the existing cluster.
Only for Contrail 5.0 for now.
Juju 2.0 is required.

Usage
-----

Once ready, deploy, configure and relate as follows:

1. Deploy.

    juju deploy contrail-command

2. Configure.

    We advise you to create configure file:

        $ cat config.yaml
        contrail-command:
            docker-registry: <docker-registry>
            image-tag: <image-tag>
            install-docker: <install-docker>
            juju-controller: <juju-controller-ip>
            juju-controller-password: <password>
            juju-ca-cert: |
                <juju-CA-certificate>
            juju-model-id: <juju-model-id>

    Fill it with

    - docker-registry: docker registry for contrail-command and contrail-command-depoyer containers
    - image-tag: tag for contrail-command and contrail-command-depoyer containers
    - install-docker: set it to false if there is other docker containers on machine with contrail-command
    - juju-controller-ip: IP of JuJu controller. You can get it from `juju show-controller` command.

            jenkins@contrail-ci:~$ juju show-controller
            jc5-cloud:
                details:
                    ...(skipped)...
                    api-endpoints: [10.0.12.99:17070]
                    ...(skipped)...

    - password: password for juju controller access. You should set password for Juju by `juju change-user-password` command.
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

    Apply config:

        juju config contrail-command --file config.yaml

3. Relate

        juju add-relation contrail-command contrail-controller

