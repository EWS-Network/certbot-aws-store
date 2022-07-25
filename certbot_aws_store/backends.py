# SPDX-License-Identifier: MPL-2.0
# Copyright 2022 John Mille <john@ews-network.net>

"""
AWS Storage backend wrappers to make it easier to manipulate values.
"""

from __future__ import annotations

import datetime
import json
import stat
from os import chmod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from certbot_aws_store.certificate import AcmeCertificate

import re
import warnings

from boto3.session import Session
from compose_x_common.aws import get_session
from compose_x_common.aws.s3 import S3_BUCKET_ARN_RE
from compose_x_common.compose_x_common import set_else_none

SECRETS_MANAGER_RE = re.compile(
    r"arn:aws(?:[\w-]+)?:secretsmanager:(?P<region>[a-z\d\-]+-\d):"
)
SECRET_ARN_RE = re.compile(
    rf"{SECRETS_MANAGER_RE.pattern}"
    r"(?P<accountid>[0-9]{12}):secret:(?P<id>(?P<name>[\S]+)(?:-[A-Za-z\d]{6}))$"
)


class AWSBackend:
    """
    Generic class for storage of the certificates
    """

    def __init__(self, prefix_path: str = "certbot-store/", session: Session = None):
        self._arn = ""
        self._prefix = prefix_path
        self.session = get_session(session)

    @property
    def arn(self) -> str:
        return self._arn

    @property
    def prefix(self) -> str:
        if self._prefix.endswith(r"/"):
            return self._prefix
        return f"{self._prefix}/"

    @arn.setter
    def arn(self, value: str):
        self._arn = self.set_arn(value)

    def set_arn(self, arn: str):
        return arn


class SecretsManagerBackend(AWSBackend):
    """
    SecretsManager storage backend
    """

    @property
    def arn(self) -> str:
        return self._arn

    @arn.setter
    def arn(self, value: str):
        self._arn = self.set_arn(value)

    @property
    def secret_name(self) -> str:
        if SECRETS_MANAGER_RE.match(self.arn) and SECRET_ARN_RE.match(self.arn):
            return SECRET_ARN_RE.match(self.arn).group("name")
        return self.arn

    def put(self, value, restore: bool = True):
        client = self.session.client("secretsmanager")
        try:
            existing_r = client.describe_secret(SecretId=self.secret_name)
            self.arn = existing_r["ARN"]
            planned_deletion = set_else_none("DeletedDate", existing_r)
            if planned_deletion and planned_deletion > datetime.datetime.utcnow():
                if restore:
                    warnings.warn(
                        UserWarning(
                            "Secret is planned for deletion. Cancelling deletion"
                        )
                    )
                    client.restore_secret(SecretId=self.arn)
                else:
                    warnings.warn(
                        UserWarning(
                            "Secret is planned for deletion. Not updating value!!!"
                        )
                    )
            client.put_secret_value(SecretId=self.secret_name, SecretString=value)
        except client.exceptions.ResourceNotFoundException:
            self.arn = client.create_secret(Name=self.secret_name, SecretString=value)[
                "ARN"
            ]


class S3Backend(AWSBackend):
    """
    Class to handle S3 backend storage
    """

    bucket_file_arn_re = re.compile(
        r"^arn:aws(?:-[a-z]+)?:s3:::(?P<bucket>\S+)::(?P<key>\S+)$"
    )

    def __init__(self, prefix_path: str = "certbot-store/", session: Session = None):
        self.bucket_name = ""
        self.key = ""
        super().__init__(prefix_path, session)

    def set_arn(self, arn: str):
        if not S3_BUCKET_ARN_RE.match(arn):
            raise ValueError(
                "S3 ARN is not valid. Got",
                arn,
                "Expected to match",
                S3_BUCKET_ARN_RE.pattern,
            )
        parts = self.bucket_file_arn_re.match(arn)
        if parts:
            self.bucket_name = parts.group("bucket")
            self.key = parts.group("key")
        return arn

    @property
    def bucket(self):
        if not self.bucket_name:
            warnings.warn("You must set the bucket name first")
            return
        resource = self.session.resource("s3")
        return resource.Bucket(self.bucket_name)

    @property
    def object(self):
        if not self.bucket or not self.key:
            warnings.warn("You must set the bucket and key first")
            return
        resource = self.session.resource("s3")
        return resource.Object(self.bucket.name, self.key)


def handle_s3_backend(
    certificate: AcmeCertificate,
    key_name: str,
    cert_content: dict,
    s3_bucket_name,
    s3_prefix_key: str,
    session: Session = None,
) -> S3Backend:
    """
    Creates the S3 backend store for public and private key. Uploads to S3.
    """
    session = get_session(session=session)
    key_backend = S3Backend(prefix_path=s3_prefix_key, session=session)
    key_backend.arn = (
        f"arn:aws:s3:::{s3_bucket_name}"
        f"::{key_backend.prefix}{certificate.acme_account.endpoint}/"
        f"{certificate.acme_account.account_id}/{certificate.hostname}/{key_name}"
    )
    key_backend.object.put(Body=cert_content[key_name])
    return key_backend


def handle_secretsmanager_secret_per_cert(
    cert: AcmeCertificate,
    key_name: str,
    cert_content: dict,
    prefix_key: str,
    session: Session = None,
) -> SecretsManagerBackend:
    session = get_session(session)
    key_backend = SecretsManagerBackend(prefix_path=prefix_key, session=session)
    key_backend.arn = (
        f"{key_backend.prefix}"
        f"{cert.acme_account.endpoint}/{cert.acme_account.account_id}/"
        f"{cert.hostname}/{key_name}"
    )
    key_backend.put(cert_content[key_name])
    return key_backend


def handle_secretsmanager_secret_all_certs(
    cert: AcmeCertificate,
    cert_content: dict,
    prefix_key: str,
    session: Session = None,
) -> SecretsManagerBackend:
    content: dict = {}
    for file, attribute in cert.files.items():
        content[attribute] = cert_content[file]
    session = get_session(session)
    key_backend = SecretsManagerBackend(prefix_path=prefix_key, session=session)
    key_backend.arn = (
        f"{key_backend.prefix}"
        f"{cert.acme_account.endpoint}/{cert.acme_account.account_id}/"
        f"{cert.hostname}"
    )
    key_backend.put(json.dumps(content))
    return key_backend


def pull_from_secrets_manager_aio(
    destination_folder: str,
    secret_arn: str,
    private_file_name: str = None,
    session: Session = None,
) -> None:
    from certbot_aws_store.certificate import AcmeCertificate

    session = get_session(session)
    client = session.client("secretsmanager")
    try:
        secret_value = json.loads(
            client.get_secret_value(SecretId=secret_arn)["SecretString"]
        )
    except client.exceptions.ResourceNotFoundException as error:
        print(error)
        raise
    except json.JSONDecodeError:
        print("Failed to parse SecretString to JSON")
        raise
    for file_name, attribute in AcmeCertificate.files.items():
        file_path = f"{destination_folder}/{file_name}"
        with open(file_path, "w") as fd:
            fd.write(secret_value[attribute])
        set_certs_permissions(
            file_name,
            file_path,
            private_file_name or AcmeCertificate.private_key_file_name,
        )


def pull_from_secretsmanager_secret_per_cert(
    destination_folder: str,
    locations: dict,
    private_file_name: str = None,
    session: Session = None,
) -> None:
    from certbot_aws_store.certificate import AcmeCertificate

    session = get_session(session)
    client = session.client("secretsmanager")
    for file_name, attribute in AcmeCertificate.files.items():
        file_path = f"{destination_folder}/{file_name}"
        try:
            with open(file_path, "w") as fd:
                secret_value = client.get_secret_value(SecretId=locations[attribute])[
                    "SecretString"
                ]
                fd.write(secret_value)
            set_certs_permissions(
                file_name,
                file_path,
                private_file_name or AcmeCertificate.private_key_file_name,
            )
        except client.exceptions.ResourceNotFoundException as error:
            print(error)
            raise


def pull_from_s3(
    destination_folder: str,
    locations: dict,
    private_file_name: str = None,
    session: Session = None,
):
    from certbot_aws_store.certificate import AcmeCertificate

    session = get_session(session)
    for file_name, attribute in AcmeCertificate.files.items():
        file_path = f"{destination_folder}/{file_name}"
        parts = S3Backend.bucket_file_arn_re.match(locations[attribute])
        if not parts:
            raise ValueError(
                locations[attribute],
                "is not a valid S3 ARN",
                S3Backend.bucket_file_arn_re.pattern,
            )
        resource = session.resource("s3").Object(
            parts.group("bucket"), parts.group("key")
        )
        resource.download_file(file_path)
        set_certs_permissions(
            file_name,
            file_path,
            private_file_name or AcmeCertificate.private_key_file_name,
        )


def set_certs_permissions(
    file_name: str, file_path: str, private_file_name: str
) -> None:
    if file_name == private_file_name:
        chmod(
            file_path,
            stat.S_IWRITE | stat.S_IRUSR,
        )
    else:
        chmod(
            file_path,
            stat.S_IWRITE | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH,
        )
