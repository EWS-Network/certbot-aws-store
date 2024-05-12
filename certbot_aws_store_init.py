#!/usr/bin/env python
#  SPDX-License-Identifier: MPL-2.0
#  Copyright 2022 John Mille <john@ews-network.net>

"""
Script to initialize the AWS Account with the necessary resources to have successful deployment of certbot-aws-store
"""
import json
import sys
from argparse import ArgumentParser
from os import path

from boto3.session import Session

try:
    from troposphere import (
        AWS_NO_VALUE,
        AWS_PARTITION,
        AWS_REGION,
        AWS_STACK_ID,
        AWS_STACK_NAME,
        GetAtt,
        Join,
        Output,
        Parameter,
        Ref,
        Sub,
        Tags,
        Template,
        s3,
    )
    from troposphere.dynamodb import (
        AttributeDefinition,
        GlobalTable,
        KeySchema,
        ReplicaSpecification,
        StreamSpecification,
    )

except ImportError:
    print(
        "To use the init script, you must install tropophere. "
        "Either run `pip install certbot-aws-store[init]` or `pip install troposphere`"
    )

DEFAULT_BUCKET_NAME = (
    f"{Session().client('sts').get_caller_identity()['Account']}-cerbot-store"
)


def create_bucket(template: Template) -> s3.Bucket:
    bucket_name_param = template.add_parameter(Parameter("BucketName", Type="String"))
    bucket = s3.Bucket(
        "CertbotStoreBucket",
        BucketName=Ref(bucket_name_param),
        BucketEncryption=s3.BucketEncryption(
            ServerSideEncryptionConfiguration=[
                s3.ServerSideEncryptionRule(
                    BucketKeyEnabled=True,
                    ServerSideEncryptionByDefault=s3.ServerSideEncryptionByDefault(
                        SSEAlgorithm="AES256"
                    ),
                )
            ]
        ),
        PublicAccessBlockConfiguration=s3.PublicAccessBlockConfiguration(
            BlockPublicAcls=True,
            BlockPublicPolicy=True,
            IgnorePublicAcls=True,
            RestrictPublicBuckets=True,
        ),
        ObjectLockEnabled=False,
        Tags=Tags(
            Name=Ref(bucket_name_param),
            StackId=Ref(AWS_STACK_ID),
            StackName=Ref(AWS_STACK_NAME),
        ),
    )
    template.add_resource(
        s3.BucketPolicy(
            "CertbotStoreBucketPolicy",
            DependsOn=[bucket.title],
            Bucket=Ref(bucket),
            PolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowSSLRequestsOnly",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:*",
                        "Effect": "Deny",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        "Resource": [
                            Sub(f"arn:${{{AWS_PARTITION}}}:s3:::${{{bucket.title}}}"),
                            Sub(f"arn:${{{AWS_PARTITION}}}:s3:::${{{bucket.title}}}/*"),
                        ],
                    }
                ],
            },
        )
    )
    template.add_resource(bucket)
    return bucket


def create_global_table(
    replica_regions: list[str], template: Template, parameters: dict
) -> GlobalTable:
    primary_region_param = template.add_parameter(
        Parameter("PrimaryRegion", Type="String")
    )
    table_name_param = template.add_parameter(Parameter("TableName", Type="String"))
    replica_tags = Tags(
        Name=Ref(table_name_param),
        IsReplica=True,
        StackId=Ref(AWS_STACK_ID),
        StackName=Ref(AWS_STACK_NAME),
        PrimaryRegion=Ref(primary_region_param),
    )
    cfn_replica_regions: list[ReplicaSpecification] = [
        ReplicaSpecification(
            Region=Ref(primary_region_param),
            TableClass="STANDARD_INFREQUENT_ACCESS",
            Tags=replica_tags,
        )
    ]
    for count, region in enumerate(replica_regions):
        region_param = template.add_parameter(
            Parameter(f"ReplicaRegion{count}", Type="String")
        )
        cfn_replica_regions.append(
            ReplicaSpecification(
                Region=Ref(region_param),
                TableClass="STANDARD_INFREQUENT_ACCESS",
                Tags=replica_tags,
            )
        )
        parameters.update({region_param.title: region})
    table = GlobalTable(
        "CertbotStoreRegistry",
        TableName=Ref(table_name_param),
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification=Ref(AWS_NO_VALUE),
        AttributeDefinitions=[
            AttributeDefinition(AttributeName="hostname", AttributeType="S"),
            AttributeDefinition(AttributeName="account_id", AttributeType="S"),
        ],
        KeySchema=[
            KeySchema(AttributeName="hostname", KeyType="HASH"),
            KeySchema(AttributeName="account_id", KeyType="RANGE"),
        ],
        Replicas=cfn_replica_regions,
    )
    if len(replica_regions) >= 1:
        setattr(
            table,
            "StreamSpecification",
            StreamSpecification(StreamViewType="NEW_AND_OLD_IMAGES"),
        )
    return table


def set_parser() -> ArgumentParser:
    init_parser = ArgumentParser("Certbot init CLI")
    init_parser.add_argument(
        "--primary-region",
        help="The primary region for the DynamoDB Table and the S3 bucket. Defaults to user session",
        required=False,
        default=Session().region_name,
    )
    init_parser.add_argument(
        "--replica-region",
        action="append",
        default=[],
        help="List of AWS Regions to set the DynamoDB replication for",
    )
    init_parser.add_argument(
        "--table-name",
        default="certbot-registry",
        help="Name of the dynamodb table to use for the certificates registry",
    )
    init_parser.add_argument(
        "--bucket-name",
        default=DEFAULT_BUCKET_NAME,
        help="Name of the S3 bucket to store the certificates into by default",
    )
    init_parser.add_argument(
        "--no-bucket",
        action="store_true",
        help="It set, the template will not add a default bucket to store the certificates into.",
    )
    init_parser.add_argument(
        "-o",
        "--output-template",
        help="Path/Name of the template to write to",
        default="certbot_resources.yaml",
    )
    return init_parser


def main():
    parser = set_parser()
    args = parser.parse_args()
    template = Template("Certbot AWS Store registry")
    parameters: dict = {
        "TableName": args.table_name,
        "PrimaryRegion": args.primary_region,
    }
    table = template.add_resource(
        create_global_table(args.replica_region, template, parameters)
    )
    template.add_output(Output("TableArn", Value=GetAtt(table, "Arn")))

    if not args.no_bucket:
        bucket = create_bucket(template)
        parameters["BucketName"] = args.bucket_name
        template.add_output(Output("BucketName", Value=Ref(bucket)))

    template_path: str = path.abspath(args.output_template)
    with open(template_path, "w") as template_fd:
        template_fd.write(template.to_yaml())
        print(f"Template written at {template_path}")
    params_path: str = (
        f"{path.abspath(path.dirname(args.output_template))}/template.params.json"
    )
    with open(params_path, "w") as params_fd:
        params_fd.write(
            json.dumps(
                [
                    {"ParameterKey": k, "ParameterValue": v}
                    for k, v in parameters.items()
                ],
                indent=2,
            )
        )
        print(f"Template parameters file written at {params_path}")
    print(
        "To deploy (create/update), run the following command",
        "aws cloudformation deploy --stack-name <STACK_NAME> "
        f"--template-file {template_path} --parameter-overrides file://{params_path}",
    )


if __name__ == "__main__":
    sys.exit(main())
