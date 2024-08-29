###############################################################################
### CDK Imports
###############################################################################
from aws_cdk import Duration, NestedStack
from aws_cdk.aws_events import Rule, RuleTargetInput, Schedule
from aws_cdk.aws_events_targets import LambdaFunction
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
        # iam_stack=None,
        lambda_stack=None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # CDK Context
        env = self.node.try_get_context("env") or "events"
        env_vars = self.node.try_get_context(env)

        # Global Variables
        events_vars = env_vars

        for rule in events_vars.get("rules", []):
            Rule(
                self,
                rule.get("name"),
                enabled=rule.get("enabled", True),
                schedule=Schedule.rate(
                    schedule_config(
                        rule.get("rate", "hours"), rule.get("duration", 1)
                    )
                ),
                targets=[
                    LambdaFunction(
                        lambda_stack.securityhub_findings_exporter,
                        event=RuleTargetInput.from_object(
                            {
                                "from_email": rule.get("from_email"),
                                "to_emails": rule.get("to_emails"),
                                "subject": rule.get("subject"),
                                "body": rule.get("body"),
                                "compliance_status_filter": rule.get(
                                    "compliance_status_filter", None
                                ),
                                "security_standard_filter": rule.get(
                                    "security_standard_filter", None
                                ),
                                "severity_filter": rule.get(
                                    "severity_filter", None
                                ),
                                "workflow_status_filter": rule.get(
                                    "workflow_status_filter", None
                                ),
                                # Merging with the default event by referencing the original event path
                                "originalEvent": RuleTargetInput.from_event_path(
                                    "$"
                                ),
                            }
                        ),
                    )
                ],
            )
