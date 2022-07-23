==================================
certbot-aws-store
==================================

Wrapper tool / function around certbot + route53 that allows to request new certificates, and store them in AWS.

Features

* Store Let's Encrypt certificates in AWS SecretsManager (default) and S3 (optional)
* Keep track of ACME account configuration and store securely in AWS SecretsManager
* Keep track of certificates issued and stored in account via DynamoDB

Pre-Requisites
================

* A function AWS Account and credentials to make API calls
* Access to DynamoDB + SecretsManager + S3 (optional)

We recommend to create the dynamodb table using the ``certbot-store-registry.template`` CFN template, otherwise
certbot-aws-store will attempt to create it programmatically.

The needed RCU/WCU should be 5/5 (default) or lower.

Install
=========

.. code-block::

    pip install certbot-aws-store --user

    python3 -m venv venv
    source venv/bin/activate
    pip install pip -U; pip install certbot-aws-store

Usage
======

As a CLI
----------


.. code-block::

    usage: Certbot store wrapper [-h] --secret SECRET --domain DOMAIN --email EMAIL [--register-to-acm] [--dry-run] [--override-folder OVERRIDE_FOLDER] [--profile PROFILE] [--s3-backend-bucket-name BUCKETNAME]
                                 [--s3-backend-prefix-key S3_PREFIX_KEY] [--split-secrets] [--secretsmanager-backend-prefix-key SECRETS_PREFIXKEY]

    optional arguments:
      -h, --help            show this help message and exit
      --secret SECRET, --secret-store-arn SECRET
                            ACME Configuration secret name/ARN
      --domain DOMAIN       Domain name for the certificate to create
      --email EMAIL         Email for the account and ToS
      --register-to-acm     Creates|Updates certificate in ACM
      --dry-run             By default, use ACME Staging.
      --override-folder OVERRIDE_FOLDER
                            Use an existing certbot folder
      --profile PROFILE     AWS Profile to use for API requests
      --s3-backend-bucket-name BUCKETNAME
                            S3 bucket to store the certificate files into
      --s3-backend-prefix-key S3_PREFIX_KEY
                            S3 Prefix path to store the certificates
      --split-secrets       If set, each certificate file gets their own secret in Secrets Manager
      --secretsmanager-backend-prefix-key SECRETS_PREFIXKEY
                            SecretsManager prefix for secret name

Example
--------

.. code-block::

    certbot-aws-store --secret dev-acme-store --override-folder certbot-store \
     --email john@ews-network.net \
    --domain test-local-0005.bdd-testing.compose-x.io \
    --s3-backend-bucket-name dev-test-bucket


Inspiration
=============

Let's Encrypt + Certbot is a goto for anyone who wishes to have free SSL certificates to use in various places.
But then the certificates management, storage, backup and so on, still has to be done.

This is an attempt at automating the storage of certificates in AWS and the associated ACME account configuration
(to avoid rate limiting).

This tool can be used as a CLI, and coming soon, an AWS Lambda Function or/and (coming soon) a CloudFormation resource.
Once installed on AWS, the registry will be automatically looked at daily to identify certificates that need to be
renewed and store the new values in appropriate places.

How does it work ?
=====================

On the first time, if the ACME secret does not exist, we consider you never used ``certbot-aws-store`` before,
and a new ACME account will be created, along with the certificate requested.

Once the certificate request is successfully completed, both the certificate and the ACME account details are saved
to secrets manager (the certificate)

Using the dynamoDB "registry" table, we store the ARN to the various files stored in AWS, along with some metadata.

For example, the following represents a certificate stored in Secrets Manager, S3 and ACM

.. code-block:: json

    {
     "hostname": "test-local-0106.bdd-testing.compose-x.io",
     "account_id": "61811954",
     "acmArn": "arn:aws:acm:eu-west-1:373709667837:certificate/82b3ab6f-5b53-4a3b-ab7d-ccd1ecb52255",
     "endpoint": "acme-staging-v02.api.letsencrypt.org",
     "expiry": "2022-10-20T22:38:59.000000+0000",
     "s3Arn": {
      "certChain": "arn:aws:s3:::dev-test-bucket::certbot/store/acme-staging-v02.api.letsencrypt.org/61812954/test-local-0106.bdd-testing.compose-x.io/chain.pem",
      "fullChain": "arn:aws:s3:::dev-test-bucket::certbot/store/acme-staging-v02.api.letsencrypt.org/61812954/test-local-0106.bdd-testing.compose-x.io/fullchain.pem",
      "privateKey": "arn:aws:s3:::dev-test-bucket::certbot/store/acme-staging-v02.api.letsencrypt.org/61812954/test-local-0106.bdd-testing.compose-x.io/privkey.pem",
      "publicKey": "arn:aws:s3:::dev-test-bucket::certbot/store/acme-staging-v02.api.letsencrypt.org/61812954/test-local-0106.bdd-testing.compose-x.io/cert.pem"
     },
     "secretsmanagerArn": "arn:aws:secretsmanager:eu-west-1:373709667837:secret:certbot/store/acme-staging-v02.api.letsencrypt.org/61812954/test-local-0106.bdd-testing.compose-x.io-HpgyTD",
     "secretsmanagerCertsArn": {}
    }

The registry will be used in the future to evaluate / list the certificates that we have and decide whether or not
a certificate should be renewed.

When stored in SecretsManager, we might implement a Lambda function to implement the rotation which would update
everything, including S3.

.. warning::

    If you use ``--dry-run`` to use the ACME staging endpoint for testing, and request the same domain name as for
    the production ACME endpoint, and store the certificate to ACM, the latest of the two updates the ACM certificate.
