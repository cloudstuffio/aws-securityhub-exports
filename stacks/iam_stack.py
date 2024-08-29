###############################################################################
### CDK Imports
###############################################################################
from os import path
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
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # CDK Context
        env = self.node.try_get_context("env") or "iam"
        env_vars = self.node.try_get_context(env)

        # Global Variables
        iam_vars = env_vars

        # Managed Policies
        managed_policies = {
            "lambda_basic_execution": "service-role/AWSLambdaBasicExecutionRole",
        }

        # Service Principals
        service_principals = {
            "lambda": "lambda.amazonaws.com",
        }

        # Lambda
        self.lambda_securityhub_findings_policy = ManagedPolicy(
            self,
            "LambdaSecurityHubFindingsPolicy",
            description=iam_vars.get(
                "securityhub_findings_policy_description",
                "Lambda Security Hub Findings Policy",
            ),
            managed_policy_name=iam_vars.get(
                "securityhub_findings_policy_name",
                "lambda-securityhub-findings-policy",
            ),
            path=iam_vars.get("securityhub_findings_policy_path", "/"),
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["securityhub:GetFindings", "ses:SendRawEmail"],
                    resources=["*"],
                ),
            ],
        )

        self.lambda_securityhub_findings_role = Role(
            self,
            "LambdaSecurityHubFindingsRole",
            assumed_by=ServicePrincipal(service_principals.get("lambda", None)),
            description=iam_vars.get(
                "securityhub_findings_role_description",
                "Lambda Security Hub Findings Role",
            ),
            managed_policies=[
                ManagedPolicy.from_aws_managed_policy_name(
                    managed_policies.get("lambda_basic_execution", None)
                ),
                self.lambda_securityhub_findings_policy,
            ],
            max_session_duration=Duration.hours(1),
            path=iam_vars.get("securityhub_findings_role_path", "/"),
            role_name=iam_vars.get(
                "securityhub_findings_role_name",
                "lambda-securityhub-findings-role",
            ),
        )
