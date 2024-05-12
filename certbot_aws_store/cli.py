#!/usr/bin/env python

"""
CLI Entrypoint for certbot-aws-store
"""
import sys
from argparse import ArgumentParser

from boto3.session import Session
from publicsuffixlist import PublicSuffixList

from .acme_store import AcmeStore
from .certbot_wrappers import request_certificate
from .certificate import AcmeCertificate


def validate_domain_names(domains: list[str]):
    """
    Validates all the domain names requested use the same public domain
    """
    psl = PublicSuffixList()
    domain = psl.publicsuffix(domains[0])
    for _domain in domains[1:]:
        if domain not in _domain:
            raise (
                "Domain name requested",
                _domain,
                "does not use the same public domain as the CN",
                domain,
                domains[0],
            )


def cli_entrypoint():
    parser = ArgumentParser("Certbot store wrapper")
    parser.add_argument(
        "--secret",
        "--secret-store-arn",
        type=str,
        required=True,
        dest="secret",
        help="ACME Account Configuration secret name/ARN",
    )
    parser.add_argument(
        "--domain",
        required=True,
        action="append",
        help="Domain name for the certificate to create",
    )
    parser.add_argument(
        "--email", required=True, type=str, help="Email for the account and ToS"
    )
    parser.add_argument(
        "--register-to-acm",
        required=False,
        default=False,
        action="store_true",
        help="Creates|Updates certificate in ACM",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        required=False,
        default=False,
        help="By default, use ACME Staging.",
    )
    parser.add_argument(
        "--override-folder",
        type=str,
        required=False,
        default=None,
        help="Use an existing certbot folder",
    )
    parser.add_argument(
        "--profile",
        type=str,
        required=False,
        default=None,
        help="AWS Profile to use for API requests",
    )
    parser.add_argument(
        "--s3-backend-bucket-name",
        type=str,
        required=False,
        dest="bucketName",
        help="S3 bucket to store the certificate files into",
    )
    parser.add_argument(
        "--s3-backend-prefix-key",
        type=str,
        required=False,
        dest="s3_prefix_key",
        default=None,
        help="S3 Prefix path to store the certificates",
    )
    parser.add_argument(
        "--split-secrets",
        action="store_true",
        default=False,
        required=False,
        help="If set, each certificate file gets their own secret in Secrets Manager",
    )
    # parser.add_argument(
    #     "--s3-backend-set-passphrase",
    #     type=bool,
    #     required=False,
    #     action="store_true",
    #     default=False,
    #     dest="setKeyPassphrase",
    # )
    parser.add_argument(
        "--secretsmanager-backend-prefix-key",
        type=str,
        dest="secrets_prefixKey",
        default="certbot/store",
        help="SecretsManager prefix for secret name",
    )

    args = parser.parse_args()
    validate_domain_names(args.domain)
    if args.profile:
        session = Session(profile_name=args.profile)
    else:
        session = Session()
    store_mgr = AcmeStore(args.secret, args.override_folder, session)
    certificate = AcmeCertificate(
        args.domain[0],
        store_mgr.staging_account if args.dry_run else store_mgr.account,
        subject_alts=args.domain[1:],
    )
    try:
        certificate_content = request_certificate(
            certificate, args.email, acme_store=store_mgr, staging=args.dry_run
        )
    except Exception as e:
        print("HERE MOFO", e)
    try:
        backends: dict = {"secretsmanager": {"prefixKey": args.secrets_prefixKey}}
        if args.bucketName:
            backends["s3"]: dict = {"bucketName": args.bucketName}
            if args.s3_prefix_key:
                backends["s3"]["prefixKey"] = args.s3_prefix_key
            certificate.save_to_backends(
                backends,
                certificate_content,
                register_to_acm=args.register_to_acm,
                split_secrets=args.split_secrets,
                session=session,
            )
        try:
            print(
                certificate.hostname,
                certificate.get_account_id(store_mgr),
                certificate.serial_number,
            )
            print(certificate.urn)
        except Exception as e:
            print("THSI IS IT", e)
    except Exception as error:
        print("HERE HER", error)
        return 1
    try:
        store_mgr.save()
        return 0
    except Exception as error:
        print("HERE AHOLE", error)
        return 1


if __name__ == "__main__":
    sys.exit(cli_entrypoint())
