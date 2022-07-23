from __future__ import annotations

from os import environ

from pynamodb.attributes import MapAttribute, UnicodeAttribute, UTCDateTimeAttribute
from pynamodb.models import Model

registry_table = environ.get("REGISTRY_TABLE", "certbot-registry")


class CertificateArns(Model):

    """
    :cvar secretsmanagerCertsArn: Mapping to each individual certificate in their own secret
    :cvar secretsmanagerArn: Secret with all the certificates in the single secret
    """

    class Meta:
        table_name = registry_table
        region = environ.get(
            "AWS_DEFAULT_REGION", environ.get("AWS_REGION", "eu-west-1")
        )

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
