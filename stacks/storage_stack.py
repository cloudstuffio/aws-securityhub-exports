###############################################################################
### CDK Imports
###############################################################################
from aws_cdk import NestedStack, RemovalPolicy
from aws_cdk.aws_s3 import (
    BlockPublicAccess,
    Bucket,
    BucketAccessControl,
    BucketEncryption,
    ObjectOwnership,
    TargetObjectKeyFormat,
)
from constructs import Construct


###############################################################################
### Stack Definition
###############################################################################
class StorageStack(NestedStack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        iam_stack=None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Global Variables
        constants_vars = self.node.try_get_context("constants")
        storage_vars = self.node.try_get_context("storage")

        self.findings_bucket = Bucket(
            self,
            "FindingsBucket",
            access_control=BucketAccessControl.PRIVATE,
            auto_delete_objects=True,
            block_public_access=BlockPublicAccess.BLOCK_ALL,
            bucket_key_enabled=True,
            # bucket_name="",
            encryption=BucketEncryption.S3_MANAGED,
            # encryption_key="",
            enforce_ssl=True,
            # event_bridge_enabled="",
            # intelligent_tiering_configurations="",
            # inventory="",
            # lifecycle_rules="",
            # metrics="",
            minimum_tls_version=1.2,
            # notifications_handler_role="",
            # notifications_skip_destination_validation="",
            object_ownership=ObjectOwnership.BUCKET_OWNER_ENFORCED,
            public_read_access=False,
            removal_policy=RemovalPolicy.DESTROY,
            # server_access_logs_bucket="",
            # server_access_logs_prefix="",
            # target_object_key_format="",
            versioned=False,
        )
