# SPDX-License-Identifier: MPL-2.0
# Copyright 2022 John Mille <john@ews-network.net>

"""
Manages the provisioning and storage of the ACME/Let's Encrypt certificate
"""

from __future__ import annotations

import datetime
import json
import os.path
import re
import warnings
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from certbot_aws_store.acme_store import AcmeStore
    from certbot_aws_store.acme_config import Account


import OpenSSL
from b_dynamodb_common.models.model_type_factory import ModelTypeFactory
from boto3.session import Session
from compose_x_common.aws import get_session
from compose_x_common.aws.acm import find_certificate_from_domain_name
from compose_x_common.compose_x_common import set_else_none
from dateutil import parser

from certbot_aws_store.backends import (
    handle_s3_backend,
    handle_secretsmanager_secret_all_certs,
    handle_secretsmanager_secret_per_cert,
    pull_from_s3,
    pull_from_secrets_manager_aio,
    pull_from_secretsmanager_secret_per_cert,
)
from certbot_aws_store.registry import REGISTRY_REGION, REGISTRY_TABLE, CertificateArns
from certbot_aws_store.utils import easy_read


class AcmeCertificate:
    certificate_file_name: str = "cert.pem"
    private_key_file_name: str = "privkey.pem"
    chain_file_name: str = "chain.pem"
    full_chain_file_name: str = "fullchain.pem"

    files: dict = {
        certificate_file_name: "publicKey",
        chain_file_name: "certChain",
        private_key_file_name: "privateKey",
        full_chain_file_name: "fullChain",
    }
    default_prefix: str = "certbot/store/"

    def __init__(
        self,
        hostname,
        acme_store_account: Account,
        subject_alts: list = None,
        table_name: str = None,
        region_name: str = None,
    ):
        """
        Init the certificate. If all you need is download, you can set acme_store_account to None

        :param str hostname:
        :param AcmeStore acme_store_account:
        :param list[str] subject_alts:
        :param str table_name:
        :param str region_name:
        """
        self._hostname = hostname
        self.alt_subjects = subject_alts if subject_alts else []
        self.registry_table = ModelTypeFactory(CertificateArns).create(
            custom_table_name=table_name or REGISTRY_TABLE,
            custom_region=region_name or REGISTRY_REGION,
        )
        self.registry_cert = self.registry_table(hash_key=self.hostname)
        self.s3_backend = None
        self.secretsmanager_backend = None
        self.certs_paths: dict = {}
        self.renewal_config: list = []
        self.acme_account = acme_store_account

    def __repr__(self):
        return self.urn

    @property
    def hostname(self) -> str:
        return self._hostname

    @property
    def hostnames(self) -> list[str]:
        """
        List with the main domain name and subject alternative names
        """
        return [self.hostname] + self.alt_subjects

    @property
    def urn(self) -> str:
        if self.exists():
            props = json.loads(self.get())
            return f"{props['endpoint']}::{props['account_id']}::{self.hostname}"
        return f"{self.acme_account.endpoint}::{self.acme_account.account_id}::{self.hostname}"

    def exists(self):
        if not self.registry_cert.exists():
            self.registry_cert.create_table()
            return False
        try:
            self.registry_cert.get(hash_key=self.hostname)
            return True
        except self.registry_cert.DoesNotExist:
            return False

    def get(self):
        cert = self.registry_cert.get(hash_key=self.hostname)
        return cert.to_json()

    @property
    def certbot_account_id(self) -> Union[str, None]:
        for _line in self.renewal_config:
            if _line.startswith("account"):
                certbot_account_id = re.sub(
                    r"[^a-zA-Z\d]+", r"", _line.split(r"=")[-1].strip()
                )
                break
        else:
            print("Unable to get the renewal information")
            return None
        return certbot_account_id

    def get_account_id(self, acme_store: AcmeStore):
        certbot_account_id = self.certbot_account_id
        if not certbot_account_id:
            return None
        for account in acme_store.config.accounts:
            if account.dirname == certbot_account_id:
                return account.account_id

    @property
    def public_key_x509(self):
        if self.files[self.certificate_file_name] not in self.certs_paths:
            return
        return OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            easy_read(self.certs_paths[self.files[self.certificate_file_name]]),
        )

    @property
    def expiry_date(self) -> Union[None, datetime.datetime]:
        if not self.public_key_x509:
            warnings.warn(
                UserWarning("Unable to determine expiry date from public key.")
            )
            return None
        return parser.parse(self.public_key_x509.get_notAfter())

    @property
    def serial_number(self) -> Union[str, None]:
        if not self.public_key_x509:
            warnings.warn(
                UserWarning("Unable to determine expiry date from public key.")
            )
            return None
        return self.public_key_x509.get_serial_number()

    def save_to_s3(
        self,
        s3_registry_arn: dict,
        backend_definition: dict,
        cert_content: dict,
        session: Session = None,
    ):
        for file_name, attribute_name in self.files.items():
            s3_backend = handle_s3_backend(
                self,
                file_name,
                cert_content,
                backend_definition["bucketName"],
                set_else_none(
                    "prefixKey", backend_definition, alt_value=self.default_prefix
                ),
                session,
            )
            s3_registry_arn.update(
                {attribute_name: {"Arn": s3_backend.arn, "Url": s3_backend.url}}
            )

    def save_to_secretsmanager(
        self,
        split_secrets: bool,
        cert_content: dict,
        backend_definition: dict,
        session: Session = None,
    ) -> Union[str, dict]:
        session = get_session(session)
        if split_secrets:
            secretsmanager_registry_arn: dict = {}
            for file_name, attribute_name in self.files.items():
                secretsmanager_backends = handle_secretsmanager_secret_per_cert(
                    self,
                    file_name,
                    cert_content,
                    prefix_key=set_else_none(
                        "prefixKey",
                        backend_definition,
                        alt_value=self.default_prefix,
                    ),
                    session=session,
                )
                secretsmanager_registry_arn.update(
                    {
                        attribute_name: secretsmanager_backends.arn,
                    }
                )
            return secretsmanager_registry_arn
        else:
            secretsmanager_backends = handle_secretsmanager_secret_all_certs(
                self,
                cert_content,
                prefix_key=set_else_none(
                    "prefixKey", backend_definition, alt_value=self.default_prefix
                ),
                session=session,
            )
            return secretsmanager_backends.arn

    def save_to_backends(
        self,
        backends: dict,
        cert_content: dict,
        register_to_acm: bool = True,
        split_secrets: bool = False,
        session: Session = None,
    ):
        session = get_session(session)
        s3_registry_arn: dict = {}
        secretsmanager_registry_arn: dict = {}
        for backend_name, backend_definition in backends.items():
            if backend_name == "s3":
                try:
                    self.save_to_s3(
                        s3_registry_arn, backend_definition, cert_content, session
                    )
                except Exception as error:
                    print(error)
                    print("Failed to save certificate to S3")
            elif backend_name == "secretsmanager":
                try:
                    secretsmanager_registry_arn = self.save_to_secretsmanager(
                        split_secrets,
                        cert_content,
                        backend_definition,
                        session,
                    )
                except Exception as error:
                    print(error)
                    print("Failed to save certificate to Secrets manager")

        acm_arn = None
        if register_to_acm:
            try:
                acm_arn = self.register_to_acm(cert_content, session)
            except Exception as error:
                print(error)
                print("Failed to save certificate to ACM")

        self.register_to_registry(s3_registry_arn, secretsmanager_registry_arn, acm_arn)

    def register_to_registry(
        self,
        s3_registry_arn: dict = None,
        secretsmanager_registry_arn: Union[str, dict] = None,
        acm_arn: str = None,
    ):
        props: dict = {
            "hostname": self.hostname,
            "expiry": self.expiry_date,
            "account_id": self.acme_account.account_id,
            "endpoint": self.acme_account.endpoint,
            "alt_subjects": self.alt_subjects,
        }
        if s3_registry_arn:
            props["s3Arn"] = s3_registry_arn
        if secretsmanager_registry_arn and isinstance(
            secretsmanager_registry_arn, dict
        ):
            props["secretsmanagerCertsArn"] = secretsmanager_registry_arn
        else:
            props["secretsmanagerArn"] = secretsmanager_registry_arn
            props["secretsmanagerCertsArn"]: dict = {}
        if acm_arn:
            props["acmArn"] = acm_arn
        registry_entry = CertificateArns(**props)

        registry_entry.save()
        return registry_entry.to_json()

    def register_to_acm(self, cert_content: dict, session: Session = None):
        session = get_session(session)
        certificate = find_certificate_from_domain_name(self.hostname, True, session)
        client = session.client("acm")
        if certificate:
            arn = certificate["CertificateArn"]
            client.import_certificate(
                CertificateArn=arn,
                Certificate=cert_content[self.certificate_file_name],
                PrivateKey=cert_content[self.private_key_file_name],
                CertificateChain=cert_content[self.chain_file_name],
            )
        else:
            cert_r = client.import_certificate(
                Certificate=cert_content[self.certificate_file_name],
                PrivateKey=cert_content[self.private_key_file_name],
                CertificateChain=cert_content[self.chain_file_name],
                Tags=[{"Key": "Name", "Value": self.hostname}],
            )
            arn = cert_r["CertificateArn"]
        return arn

    def pull(
        self,
        destination_folder: str,
        use_s3: bool = False,
        split_secrets: bool = False,
        session: Session = None,
    ):
        session = get_session(session)
        if not self.exists():
            raise ValueError(self.hostname, f"not found in table")
        details = json.loads(self.registry_cert.get(self.hostname).to_json())
        if use_s3:
            locations = set_else_none("s3Arn", details)
        elif split_secrets:
            locations = set_else_none("secretsmanagerCertsArn", details)
        else:
            locations = set_else_none("secretsmanagerArn", details)

        if not locations:
            raise ValueError(
                "Unable to determine the location of certificates from dynamodb registry"
            )

        if isinstance(locations, str) and not use_s3:
            pull_from_secrets_manager_aio(
                destination_folder, locations, self.private_key_file_name, session
            )
        elif isinstance(locations, dict) and use_s3:
            pull_from_s3(
                destination_folder, locations, self.private_key_file_name, session
            )
        else:
            pull_from_secretsmanager_secret_per_cert(
                destination_folder, locations, self.private_key_file_name, session
            )
