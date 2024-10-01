###############################################################################
### CDK Imports
###############################################################################
from aws_cdk import Duration, NestedStack
from aws_cdk.aws_iam import (
    Effect,
    ManagedPolicy,
    PolicyStatement,
    Role,
    ServicePrincipal,
)
from constructs import Construct


###############################################################################
### Stack Definition
###############################################################################
class IamStack(NestedStack):
    def __init__(
        self, scope: Construct, construct_id: str, storage_stack=None, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Global Variables
        constants_vars = self.node.try_get_context("constants")
        iam_vars = self.node.try_get_context("iam")

        # Managed Policies
        managed_policies = {
            "lambda_basic_execution": "service-role/AWSLambdaBasicExecutionRole",
        }

        # Service Principals
        service_principals = {
            "lambda": "lambda.amazonaws.com",
            "states": "states.amazonaws.com",
        }

        # Lambda
        # Fetch Findings Policy
        self.lambda_fetch_findings_policy = ManagedPolicy(
            self,
            "FetchFindingsPolicy",
            description=constants_vars.get(
                "fetch_findings_description",
                "Lambda Security Hub Fetch Findings",
            )
            + " Policy",
            managed_policy_name=constants_vars.get(
                "fetch_findings_name",
                "lambda-securityhub-fetch-findings",
            )
            + "-policy",
            path=iam_vars.get("path", "/"),
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "securityhub:GetFindings",
                    ],
                    resources=["*"],
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "s3:PutObject",
                    ],
                    resources=["*"],
                ),
            ],
        )

        # Generate CSV Policy
        self.lambda_generate_csv_policy = ManagedPolicy(
            self,
            "GenerateCsvPolicy",
            description=constants_vars.get(
                "generate_csv_description",
                "Lambda Security Hub Generate CSV",
            )
            + " Policy",
            managed_policy_name=constants_vars.get(
                "generate_csv_name",
                "lambda-securityhub-generate-csv",
            )
            + "-policy",
            path=iam_vars.get("path", "/"),
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["s3:*"],
                    resources=["*"],
                ),
            ],
        )

        # Send Email Policy
        self.lambda_send_email_policy = ManagedPolicy(
            self,
            "SendEmailPolicy",
            description=constants_vars.get(
                "send_email_description",
                "Lambda Security Hub Send Email",
            )
            + " Policy",
            managed_policy_name=constants_vars.get(
                "send_email_name",
                "lambda-securityhub-send-email",
            )
            + "-policy",
            path=iam_vars.get("path", "/"),
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["s3:*"],
                    resources=["*"],
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["ses:SendRawEmail", "ses:SendEmail"],
                    resources=["*"],
                ),
            ],
        )

        # Fetch Findings Role
        self.lambda_fetch_findings_role = Role(
            self,
            "FetchFindingsRole",
            assumed_by=ServicePrincipal(service_principals.get("lambda", None)),
            description=constants_vars.get(
                "fetch_findings_description",
                "Lambda Security Hub Fetch Findings",
            )
            + " Role",
            managed_policies=[
                ManagedPolicy.from_aws_managed_policy_name(
                    managed_policies.get("lambda_basic_execution", None)
                ),
                self.lambda_fetch_findings_policy,
            ],
            max_session_duration=Duration.hours(1),
            path=iam_vars.get("path", "/"),
            role_name=constants_vars.get(
                "fetch_findings_name",
                "lambda-securityhub-fetch-findings",
            )
            + "-role",
        )

        # Generate CSV Role
        self.lambda_generate_csv_role = Role(
            self,
            "GenerateCsvRole",
            assumed_by=ServicePrincipal(service_principals.get("lambda", None)),
            description=constants_vars.get(
                "generate_csv_description",
                "Lambda Security Hub Generate CSV",
            )
            + " Role",
            managed_policies=[
                ManagedPolicy.from_aws_managed_policy_name(
                    managed_policies.get("lambda_basic_execution", None)
                ),
                self.lambda_generate_csv_policy,
            ],
            max_session_duration=Duration.hours(1),
            path=iam_vars.get("path", "/"),
            role_name=constants_vars.get(
                "generate_csv_name",
                "lambda-securityhub-generate-csv",
            )
            + "-role",
        )

        # Send Email Role
        self.lambda_send_email_role = Role(
            self,
            "SendEmailRole",
            assumed_by=ServicePrincipal(service_principals.get("lambda", None)),
            description=constants_vars.get(
                "send_email_description",
                "Lambda Security Hub Send Email Role",
            )
            + " Role",
            managed_policies=[
                ManagedPolicy.from_aws_managed_policy_name(
                    managed_policies.get("lambda_basic_execution", None)
                ),
                self.lambda_send_email_policy,
            ],
            max_session_duration=Duration.hours(1),
            path=iam_vars.get("path", "/"),
            role_name=constants_vars.get(
                "send_email_name",
                "lambda-securityhub-send-email",
            )
            + "-role",
        )
