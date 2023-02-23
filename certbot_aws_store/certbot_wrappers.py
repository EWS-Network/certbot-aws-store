#  SPDX-License-Identifier: MPL-2.0
#  Copyright 2022 John Mille <john@ews-network.net>

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .certificate import AcmeCertificate
    from .acme_store import AcmeStore

import os
from multiprocessing import Process

from certbot.main import main

from .utils import easy_read


def provision_cert(
    email,
    domains: list[str],
    dir_path: str,
    staging: bool = False,
    accept_tos: bool = True,
    config_dir: str = None,
    logs_dir: str = None,
    work_dir: str = None,
):
    """
    Provisions a new certificate with Route53 validation
    """
    cmd = [
        "certonly",
        "-n",
        "--dns-route53",
        "-d",
        ",".join(domains),
        "--config-dir",
        config_dir or f"{dir_path}/config-dir/",
        "--work-dir",
        work_dir or f"{dir_path}/work-dir/",
        "--logs-dir",
        logs_dir or f"{dir_path}/logs-dir/",
    ]
    if staging:
        cmd.append("--test-cert")
    if accept_tos:
        cmd.append("--agree-tos")
        cmd.append("--email")
        cmd.append(email)
    main(cmd)


def find_certificate_renewal_config(top_path: str, hostname: str) -> list:
    renewal_config_file_name = f"{hostname}.conf"
    for root, dirs, files in os.walk(top_path):
        for _file in files:
            if _file == renewal_config_file_name:
                file_path = os.path.join(root, _file)
                with open(file_path) as config_fd:
                    return config_fd.readlines()


def request_certificate(
    acme_cert: AcmeCertificate, email: str, acme_store: AcmeStore, staging: bool = False
):
    if acme_cert.acme_account:
        args = (email, acme_cert.hostnames, acme_store.directory, staging)
    else:
        args = (email, acme_cert.hostnames, acme_store.directory, staging, True)
    process = Process(
        target=provision_cert,
        args=args,
    )
    process.start()
    process.join()
    live_path = f"{acme_store.config_dir}/live/{acme_cert.hostname}"
    certificate_files: dict = {}
    for file, attribute in acme_cert.files.items():
        file_path = f"{live_path}/{file}"
        certificate_files[file]: str = easy_read(file_path)
        acme_cert.certs_paths[attribute]: str = os.path.abspath(file_path)
    acme_cert.renewal_config = find_certificate_renewal_config(
        acme_store.directory, acme_cert.hostname
    )
    if not acme_cert.acme_account:
        acme_store.set_execution_accounts()
        acme_cert.acme_account = (
            acme_store.staging_account if staging else acme_store.account
        )
    return certificate_files
