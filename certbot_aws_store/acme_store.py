# SPDX-License-Identifier: MPL-2.0
# Copyright 2022 John Mille <john@ews-network.net>

"""
Manages the config-dir/accounts settings to avoid creating new accounts for every new certificate.
"""
import datetime
import json
import os
import stat
from shutil import rmtree
from tempfile import TemporaryDirectory
from urllib.parse import urlparse

from boto3.session import Session
from compose_x_common.aws import get_session
from dateutil import parser as dateparser

from certbot_aws_store.acme_config import Account, AcmeConfig
from certbot_aws_store.backends import SECRET_ARN_RE
from certbot_aws_store.utils import easy_read


class AcmeStore:
    pkey_file_name = "private_key.json"
    regr_file_name = "regr.json"
    meta_file_name = "meta.json"

    files = {
        pkey_file_name: "privateKey",
        regr_file_name: "registration",
        meta_file_name: "metadata",
    }

    accounts_dir_name: str = "accounts"

    def __init__(
        self,
        certs_store_arn: str,
        override_directory: str = None,
        session: Session = None,
    ):
        self._store_arn = certs_store_arn
        self.session = get_session(session)
        self.staging_account = None
        self.account = None
        self.backup_config = None
        if not override_directory:
            self.temp_dir = TemporaryDirectory()
            self.directory = self.temp_dir.name
            self.accounts_path = f"{self.config_dir}/{self.accounts_dir_name}"
            os.makedirs(self.accounts_path, exist_ok=True)
        else:
            self.directory = override_directory
            try:
                self.accounts_path = find_accounts_dir(override_directory)
            except OSError:
                self.accounts_path = f"{self.config_dir}/{self.accounts_dir_name}"
                if not os.path.exists(self.accounts_path):
                    os.makedirs(self.accounts_path, exist_ok=True)
        self.init_pull()

    @property
    def existing_accounts(self) -> list[Account]:
        return get_acme_accounts(self.accounts_path)

    @property
    def config_dir(self) -> str:
        return f"{self.directory}/config-dir"

    @property
    def logs_dir(self) -> str:
        return f"{self.directory}/logs-dir"

    @property
    def work_dir(self) -> str:
        return f"{self.directory}/work-dir"

    @property
    def config(self) -> AcmeConfig:
        accounts = get_acme_accounts(self.accounts_path)
        return AcmeConfig(accounts=accounts)

    def init_pull(
        self,
    ):
        client = self.session.client("secretsmanager")
        try:
            config_r = client.get_secret_value(SecretId=self.secret_name)
            config_content = json.loads(config_r["SecretString"])
            config_content["store_arn"] = config_r["ARN"]
            self._store_arn = config_r["ARN"]
            config = AcmeConfig(**config_content)
            self.layout_accounts_folders(config)
        except client.exceptions.ResourceNotFoundException:
            print(
                f"Secret {self._store_arn} does not exist. Will initialize after first certificate"
            )
        except Exception as error:
            print(error)
            raise
        self.set_execution_accounts()

    def layout_accounts_folders(self, config: AcmeConfig):
        for endpoint, accounts in accounts_per_endpoints(config).items():
            directory_path = create_account_endpoint_dirs(self.accounts_path, endpoint)
            for account in accounts:
                _account_path = f"{directory_path}/{account.dirname}"
                os.makedirs(_account_path, exist_ok=True)
                write_accounts_files(_account_path, account)
        self.backup_config = AcmeConfig(accounts=get_acme_accounts(self.accounts_path))

    def set_execution_accounts(self):
        now = datetime.datetime.now(tz=None)
        for endpoint, accounts in accounts_per_endpoints(self.config).items():
            latest_account = accounts[0]
            latest_account_path = (
                f"{self.config_dir}/{self.accounts_dir_name}"
                f"/{endpoint}/directory/{accounts[0].dirname}"
            )
            diff = now - get_meta_creation_dt(latest_account)
            to_clear: list = []
            for account in accounts:
                _account_path = (
                    f"{self.config_dir}/{self.accounts_dir_name}"
                    f"/{endpoint}/directory/{account.dirname}"
                )
                to_clear.append(_account_path)
                created_on = get_meta_creation_dt(account)
                if not diff or (diff and diff > (now - created_on)):
                    diff = now - created_on
                    latest_account = account
                    latest_account_path = _account_path
            set_latest_endpoint_account(
                endpoint, latest_account, latest_account_path, to_clear
            )
            if latest_account.is_staging():
                self.staging_account = latest_account
            else:
                self.account = latest_account

    @property
    def secret_name(self) -> str:
        if SECRET_ARN_RE.match(self._store_arn):
            return SECRET_ARN_RE.match(self._store_arn).group("name")
        else:
            return self._store_arn

    def save(self):
        client = self.session.client("secretsmanager")
        secret_value = AcmeConfig(
            accounts=self.merge_used_accounts_with_backup()
        ).json()
        print(
            "Saving accounts",
            [
                (_act.account_id, _act.endpoint)
                for _act in self.merge_used_accounts_with_backup()
            ],
        )
        try:
            client.put_secret_value(SecretId=self._store_arn, SecretString=secret_value)
        except client.exceptions.ResourceNotFoundException:
            client.create_secret(
                Name=self.secret_name,
                SecretString=secret_value,
                Tags=[
                    {"Key": "Name", "Value": self.secret_name},
                    {"Key": "certbot_route53_store", "Value": str(True)},
                ],
            )
        except Exception as error:
            print(error)

    def merge_used_accounts_with_backup(self) -> list[Account]:
        if not self.backup_config or not isinstance(self.backup_config, AcmeConfig):
            return self.config.accounts
        at_del_accounts = self.config.accounts
        to_add: list = []
        for account in at_del_accounts:
            for _bkp_account in self.backup_config.accounts:
                if account.endpoint != _bkp_account.endpoint:
                    continue
                if account.account_id == _bkp_account.account_id:
                    continue
                to_add.append(_bkp_account)
        at_del_accounts += to_add
        return at_del_accounts


def create_account_endpoint_dirs(accounts_path: str, endpoint: str) -> str:
    endpoint_path = f"{accounts_path}/{endpoint}"
    if not os.path.exists(endpoint_path):
        os.makedirs(endpoint_path, exist_ok=True)
    os.chmod(f"{endpoint_path}", stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
    directory_path = f"{endpoint_path}/directory"
    if not os.path.exists(directory_path):
        os.makedirs(directory_path, exist_ok=True)
    os.chmod(f"{directory_path}", stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
    return directory_path


def set_latest_endpoint_account(
    endpoint: str, account: Account, account_path: str, to_clear: list
):
    print(f"Latest {endpoint} account: {account.dirname} - {account.account_id}")
    for _dir_to_remove in to_clear:
        if _dir_to_remove == account_path:
            continue
        rmtree(_dir_to_remove)
    if not os.path.exists(account_path):
        os.makedirs(account_path, exist_ok=True)
    elif os.path.exists(account_path) and not os.path.isdir(account_path):
        raise OSError(account_path, "exists but is not a directory")


def write_accounts_files(account_path: str, account: Account) -> None:
    """
    Creates the account folders, writes down the private_key.json and regr.json
    """
    print("Import for account", account.account_id, account.endpoint, account_path)
    private_key_path = f"{account_path}/{AcmeStore.pkey_file_name}"
    try:
        with open(private_key_path) as fd:
            key_content = fd.read()
            if set(key_content) == set(account.privateKey):
                print(
                    private_key_path, "already exists and is identical. Nothing to do"
                )
    except OSError:
        with open(private_key_path, "w") as fd:
            if isinstance(account.privateKey, str):
                fd.write(account.privateKey)
            elif isinstance(account.privateKey, dict):
                fd.write(json.dumps(account.privateKey))
        os.chmod(private_key_path, stat.S_IRUSR)

    regr_key_path = f"{account_path}/{AcmeStore.regr_file_name}"
    try:
        with open(regr_key_path) as fd:
            key_content = fd.read()
            if set(key_content) == set(account.registration):
                print(regr_key_path, "already exists and is identical. Nothing to do")
    except OSError:
        with open(regr_key_path, "w") as fd:
            if isinstance(account.registration, str):
                fd.write(account.registration)
            elif isinstance(account.registration, dict):
                fd.write(json.dumps(account.registration))
        os.chmod(
            regr_key_path,
            stat.S_IWRITE | stat.S_IRUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH,
        )

    meta_key_path = f"{account_path}/{AcmeStore.meta_file_name}"
    try:
        with open(meta_key_path) as fd:
            key_content = fd.read()
            if set(key_content) == set(account.meta):
                print(meta_key_path, "already exists and is identical. Nothing to do")
    except OSError:
        with open(meta_key_path, "w") as fd:
            if isinstance(account.meta, str):
                fd.write(account.meta)
            elif isinstance(account.meta, dict):
                fd.write(json.dumps(account.meta))
        os.chmod(
            meta_key_path,
            stat.S_IWRITE | stat.S_IRUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH,
        )


def find_accounts_dir(certs_root_path, accounts_folder_name: str = "accounts") -> str:
    """
    For a given path, returns the path to ``accounts`` folder.

    :raises: IOError if ``accounts_folder_name`` not found in tree
    """
    for root, dirs, files in os.walk(certs_root_path):
        for _dir in dirs:
            if _dir == accounts_folder_name:
                dir_path = os.path.join(root, _dir)
                if not os.path.isdir(dir_path):
                    raise TypeError(dir_path, "is not a directory, yet exists.")
                return dir_path
    raise OSError(
        f"No folder named {accounts_folder_name} found in {certs_root_path} tree"
    )


def get_acme_accounts(
    accounts_path: str,
) -> list[Account]:
    """

    :param str accounts_path:
    :return: list of accounts
    :rtype: list[Account]
    """
    accounts: list = []
    for root, dirs, files in os.walk(accounts_path):
        if AcmeStore.pkey_file_name not in files:
            continue
        for file in files:
            if file == AcmeStore.pkey_file_name:
                private_key_path = os.path.join(root, file)
                top_dir = os.path.split(private_key_path)[0]
                top_path = os.path.normpath(top_dir)
                reg_key_path = os.path.join(top_dir, AcmeStore.regr_file_name)
                meta_key_path = os.path.join(top_dir, AcmeStore.meta_file_name)
                account_parts = top_path.split(os.sep)[3:]
                reg_key_content = easy_read(reg_key_path)
                meta_content = easy_read(meta_key_path)
                account_uri = json.loads(reg_key_content)["uri"]
                acme_account = urlparse(account_uri)
                acme_account_id = os.path.split(acme_account.path)[-1]
                account = Account(
                    account_id=acme_account_id,
                    privateKey=easy_read(private_key_path),
                    registration=reg_key_content,
                    meta=meta_content,
                    created_on=datetime.datetime.replace(
                        dateparser.parse(json.loads(meta_content)["creation_dt"]),
                        tzinfo=None,
                    ).isoformat(),
                    dirname=account_parts[-1],
                    endpoint=acme_account.netloc,
                )
                accounts.append(account)
    return accounts


def get_meta_creation_dt(account: Account) -> datetime.datetime:
    if isinstance(account.meta, str):
        metadata = json.loads(account.meta)
        created_on = datetime.datetime.replace(
            dateparser.parse(metadata["creation_dt"]), tzinfo=None
        )
    elif isinstance(account.meta, dict):
        created_on = datetime.datetime.replace(
            dateparser.parse(account.meta["creation_dt"]), tzinfo=None
        )
    else:
        raise TypeError(
            "account.meta is not valid type. Got",
            type(account.meta),
            "expected one of",
            (str, dict),
        )
    return created_on


def accounts_per_endpoints(config: AcmeConfig) -> dict[str, list[Account]]:
    endpoints_to_accounts: dict = {}
    for account in config.accounts:
        if account.endpoint not in endpoints_to_accounts.keys():
            endpoints_to_accounts[account.endpoint]: list = [account]
        else:
            endpoints_to_accounts[account.endpoint].append(account)
    return endpoints_to_accounts
