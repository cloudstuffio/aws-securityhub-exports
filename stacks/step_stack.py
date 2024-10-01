###############################################################################
### CDK Imports
###############################################################################
from aws_cdk import Duration, NestedStack
from aws_cdk.aws_logs import LogGroup
from aws_cdk.aws_stepfunctions import (
    Choice,
    Condition,
    LogLevel,
    LogOptions,
    Pass,
    StateMachine,
    StateMachineType,
    TaskInput,
)
from aws_cdk.aws_stepfunctions_tasks import LambdaInvoke
from constructs import Construct
from aws_cdk.aws_iam import (
    Effect,
    ManagedPolicy,
    PolicyStatement,
    Role,
    ServicePrincipal,
)


###############################################################################
### Stack Definition
###############################################################################
class StepStack(NestedStack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        iam_stack=None,
        lambda_stack=None,
        # storage_stack=None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Global Variables
        constants_vars = self.node.try_get_context("constants")
        iam_vars = self.node.try_get_context("iam")
        storage_vars = self.node.try_get_context("storage")

        # Step Function Execution Policy
        self.step_function_policy = ManagedPolicy(
            self,
            "StepFunctionExecutionPolicy",
            description=constants_vars.get(
                "step_function_description",
                "Security Hub Exporter Workflow",
            )
            + " Policy",
            managed_policy_name=constants_vars.get(
                "step_function_name",
                "securityhub-exporter-workflow",
            )
            + "-policy",
            path=iam_vars.get("path", "/"),
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "logs:CreateLogDelivery",
                        "logs:CreateLogStream",
                        "logs:GetLogDelivery",
                        "logs:UpdateLogDelivery",
                        "logs:DeleteLogDelivery",
                        "logs:ListLogDeliveries",
                        "logs:PutLogEvents",
                        "logs:PutResourcePolicy",
                        "logs:DescribeResourcePolicies",
                        "logs:DescribeLogGroups",
                    ],
                    resources=["*"],
                ),
            ],
        )

        # Step Function Execution Role
        self.step_function_role = Role(
            self,
            "StepFunctionExecutionRole",
            assumed_by=ServicePrincipal("states.amazonaws.com"),
            description=constants_vars.get(
                "step_function_description",
                "Security Hub Exporter Workflow",
            )
            + " Role",
            managed_policies=[
                ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaRole"
                ),
                self.step_function_policy,
            ],
            role_name=constants_vars.get(
                "step_function_name",
                "securityhub-exporter-workflow",
            )
            + "-role",
        )

        # Initialize Defaults Pass State
        initialize_defaults = Pass(
            self,
            "Initialize Defaults",
            parameters={
                "MergedParameters.$": 'States.JsonMerge(States.StringToJson(\'{"BodyText": "Please find the attached CSV file containing the filtered AWS Security Hub findings.", "ComplianceStatusFilter": null, "SecurityStandardFilter": null, "SeverityFilter": null, "WorkflowStatusFilter": null, "Subject": "AWS Security Hub Findings" }\'), $$.Execution.Input, false)'
            },
            result_path="$.Parameters",
        )

        # Set Missing Parameters Pass State
        set_missing_parameters = Pass(
            self,
            "Set Missing Parameters",
            parameters={
                "BodyText.$": "$.Parameters.MergedParameters.BodyText",
                "ComplianceStatusFilter.$": "$.Parameters.MergedParameters.ComplianceStatusFilter",
                "SecurityStandardFilter.$": "$.Parameters.MergedParameters.SecurityStandardFilter",
                "SeverityFilter.$": "$.Parameters.MergedParameters.SeverityFilter",
                "Subject.$": "$.Parameters.MergedParameters.Subject",
                "WorkflowStatusFilter.$": "$.Parameters.MergedParameters.WorkflowStatusFilter",
            },
            result_path="$.Parameters",
        )

        # Fetch Findings without Token Lambda Task
        fetch_findings_without_token = LambdaInvoke(
            self,
            "Fetch Findings without Token",
            lambda_function=lambda_stack.fetch_findings_function,
            result_path="$.TaskOutput",
            payload=TaskInput.from_object(
                {
                    "BodyText.$": "$.Parameters.BodyText",
                    "BucketName.$": "$.BucketName",
                    "ComplianceStatusFilter.$": "$.Parameters.ComplianceStatusFilter",
                    "RecipientEmails.$": "$.RecipientEmails",
                    "SecurityStandardFilter.$": "$.Parameters.SecurityStandardFilter",
                    "SenderEmail.$": "$.SenderEmail",
                    "SeverityFilter.$": "$.Parameters.SeverityFilter",
                    "Subject.$": "$.Parameters.Subject",
                    "WorkflowStatusFilter.$": "$.Parameters.WorkflowStatusFilter",
                }
            ),
        )

        # Fetch Findings with Token Lambda Task
        fetch_findings_with_token = LambdaInvoke(
            self,
            "Fetch Findings with Token",
            lambda_function=lambda_stack.fetch_findings_function,
            result_path="$.TaskOutput",
            payload=TaskInput.from_object(
                {
                    "BodyText.$": "$.Parameters.BodyText",
                    "BucketName.$": "$.BucketName",
                    "ComplianceStatusFilter.$": "$.Parameters.ComplianceStatusFilter",
                    "NextToken.$": "$.TaskOutput.Payload.NextToken",
                    "RecipientEmails.$": "$.RecipientEmails",
                    "SecurityStandardFilter.$": "$.Parameters.SecurityStandardFilter",
                    "SenderEmail.$": "$.SenderEmail",
                    "SeverityFilter.$": "$.Parameters.SeverityFilter",
                    "Subject.$": "$.Parameters.Subject",
                    "WorkflowStatusFilter.$": "$.Parameters.WorkflowStatusFilter",
                }
            ),
        )

        # Generate CSV Lambda Task
        generate_csv = LambdaInvoke(
            self,
            "Generate CSV",
            lambda_function=lambda_stack.generate_csv_function,
            result_path="$.OutputCsv",
            payload=TaskInput.from_object(
                {
                    "BucketName.$": "$.BucketName",
                    "Prefix.$": "$.TaskOutput.Payload.Prefix",
                }
            ),
        )

        # Send Email Lambda Task
        send_email = LambdaInvoke(
            self,
            "Send Email",
            lambda_function=lambda_stack.send_email_function,
            payload=TaskInput.from_object(
                {
                    "BodyText.$": "$.Parameters.BodyText",
                    "BucketName.$": "$.BucketName",
                    "OutputCsv.$": "$.OutputCsv.Payload",
                    "RecipientEmails.$": "$.RecipientEmails",
                    "SenderEmail.$": "$.SenderEmail",
                    "Subject.$": "$.Parameters.Subject",
                }
            ),
        )

        # Check for NextToken Choice State
        check_for_next_token = Choice(self, "Check for NextToken")

        # Define the workflow
        workflow_definition = (
            initialize_defaults.next(set_missing_parameters)
            .next(fetch_findings_without_token)
            .next(check_for_next_token)
        )

        check_for_next_token.when(
            Condition.is_present("$.TaskOutput.Payload.NextToken"),
            fetch_findings_with_token.next(check_for_next_token),
        ).otherwise(generate_csv.next(send_email))

        # State Machine Log Group
        log_group = LogGroup(self, "SecurityHubStateMachineLogGroup")

        # State Machine
        self.state_machine = StateMachine(
            self,
            "SecurityHubStateMachine",
            comment="Security Hub Findings Workflow",
            definition=workflow_definition,
            logs=LogOptions(
                destination=log_group,
                include_execution_data=True,
                level=LogLevel.ALL,
            ),
            role=self.step_function_role,
            state_machine_type=StateMachineType.STANDARD,
            timeout=Duration.hours(15),
        )
