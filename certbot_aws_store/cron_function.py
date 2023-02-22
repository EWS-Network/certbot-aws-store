#  SPDX-License-Identifier: MPL-2.0
#  Copyright 2022 John Mille <john@ews-network.net>

"""
Lambda function to run on a schedule that will scan all the items in the DynamoDB certs registry, evaluate which ones
to renew, and trigger said renewal.
"""

import json

from boto3.session import Session
from compose_x_common.compose_x_common import set_else_none

from certbot_aws_store.registry import get_certs_to_renew


def certs_to_renew_inventory(event, context):
    """
    Main entry point for the Lambda function.

    :param event: The event passed by the AWS Lambda service.
    :param context: The context passed by the AWS Lambda service.
    :return: The response to be returned to the AWS Lambda service.
    """
    session = Session()
    expiry = int(set_else_none("CertsExpiryInDays", event, 21))
    _certs_to_renew = get_certs_to_renew(expiry)


def renew_certificate(event, context):
    """
    Function to handle a given certificate to renew by its hostname

    :param event: The event passed by the AWS Lambda service.
    :param context: The context passed by the AWS Lambda service.
    """
