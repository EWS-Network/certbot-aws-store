from __future__ import annotations

from datetime import datetime, timedelta
from os import environ

from pynamodb.attributes import MapAttribute, UnicodeAttribute, UTCDateTimeAttribute
from pynamodb.models import Model

REGISTRY_TABLE = environ.get("REGISTRY_TABLE", "certbot-registry")
REGISTRY_REGION = environ.get(
    "AWS_DEFAULT_REGION", environ.get("AWS_REGION", "eu-west-1")
)


class CertificateArns(Model):

    """
    :cvar secretsmanagerCertsArn: Mapping to each individual certificate in their own secret
    :cvar secretsmanagerArn: Secret with all the certificates in the single secret
    """

    class Meta:
        table_name = REGISTRY_TABLE
        region = REGISTRY_REGION

    hostname = UnicodeAttribute(hash_key=True)
    account_id = UnicodeAttribute(null=False)
    endpoint = UnicodeAttribute(null=False)
    expiry = UTCDateTimeAttribute(null=True)
    s3Arn = MapAttribute(
        certChain=UnicodeAttribute(null=False),
        fullChain=UnicodeAttribute(null=False),
        privateKey=UnicodeAttribute(null=False),
        publicKey=UnicodeAttribute(null=False),
        passphrase=UnicodeAttribute(null=True),
    )
    secretsmanagerCertsArn = MapAttribute(
        privateKey=UnicodeAttribute(null=False),
        publicKey=UnicodeAttribute(null=False),
        certChain=UnicodeAttribute(null=False),
        fullChain=UnicodeAttribute(null=False),
    )
    secretsmanagerArn = UnicodeAttribute(null=True)
    acmArn = UnicodeAttribute(null=True)


def get_certs_to_renew(expires_in_days: int = 28):
    """
    Returns list of certificates that have an expiry in expires_in_days.
    Defaults to 28 days, which ensures that we are past the 60 days default
    range set by Let's Encrypt

    :param int expires_in_days:
    """
    in_future: datetime = datetime.utcnow() + timedelta(days=expires_in_days)
    to_renew = CertificateArns().scan(CertificateArns.expiry < in_future)
    return to_renew
