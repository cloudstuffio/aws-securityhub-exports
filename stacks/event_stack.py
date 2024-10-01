###############################################################################
### CDK Imports
###############################################################################
from aws_cdk import Duration, NestedStack
from aws_cdk.aws_events import Rule, RuleTargetInput, Schedule
from aws_cdk.aws_events_targets import LambdaFunction, SfnStateMachine
from constructs import Construct


###############################################################################
### Functions
###############################################################################
def schedule_config(rate, duration):
    schedule_options = {
        "minutes": Duration.minutes(duration),
        "hours": Duration.hours(duration),
        "days": Duration.days(duration),
    }
    return schedule_options.get(rate, Duration.hours(1))


###############################################################################
### Stack Definition
###############################################################################
class EventStack(NestedStack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        step_stack=None,
        storage_stack=None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Global Variables
        constants_vars = self.node.try_get_context("constants")
        events_vars = self.node.try_get_context("events")

        for rule in events_vars.get("rules", []):
            Rule(
                self,
                rule.get("name"),
                enabled=rule.get("enabled", True),
                schedule=Schedule.rate(
                    schedule_config(
                        rule.get("rate", "days"), rule.get("duration", 1)
                    )
                ),
                targets=[
                    SfnStateMachine(
                        step_stack.state_machine,
                        input=RuleTargetInput.from_object(
                            {
                                "BucketName": storage_stack.findings_bucket.bucket_name,
                                "SenderEmail": rule.get("from_email"),
                                "RecipientEmails": rule.get("to_emails"),
                                "Subject": rule.get("subject"),
                                "BodyText": rule.get("body"),
                                "ComplianceStatusFilter": rule.get(
                                    "compliance_status_filter", None
                                ),
                                "SecurityStandardFilter": rule.get(
                                    "security_standard_filter", None
                                ),
                                "SeverityFilter": rule.get(
                                    "severity_filter", None
                                ),
                                "WorkflowStatusFilter": rule.get(
                                    "workflow_status_filter", None
                                ),
                            }
                        ),
                    )
                ],
            )
