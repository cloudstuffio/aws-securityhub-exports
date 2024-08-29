###############################################################################
### CDK Imports
###############################################################################
import os
from aws_cdk import Duration, NestedStack
from aws_cdk.aws_lambda import (
    ApplicationLogLevel,
    Architecture,
    Code,
    Function,
    LoggingFormat,
    Runtime,
    SystemLogLevel,
    Tracing,
)
from constructs import Construct


###############################################################################
### Stack Definition
###############################################################################
class LambdaStack(NestedStack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        iam_stack=None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # CDK Context
        env = self.node.try_get_context("env") or "lambda"
        env_vars = self.node.try_get_context(env)

        # Global Variables
        lambda_vars = env_vars

        # Environment Variables
        environment_variables = {}

        # Lambda Lookup Options
        app_log_level_options = {
            "debug": ApplicationLogLevel.DEBUG,
            "error": ApplicationLogLevel.ERROR,
            "fatal": ApplicationLogLevel.FATAL,
            "info": ApplicationLogLevel.INFO,
            "trace": ApplicationLogLevel.TRACE,
            "warn": ApplicationLogLevel.WARN,
        }

        arch_options = {
            "arm64": Architecture.ARM_64,
            "x86_64": Architecture.X86_64,
        }

        log_format_options = {
            "json": LoggingFormat.JSON,
            "text": LoggingFormat.TEXT,
        }

        runtime_type = {
            "python3.12": Runtime.PYTHON_3_12,
        }

        system_log_level_options = {
            "debug": SystemLogLevel.DEBUG,
            "info": SystemLogLevel.INFO,
            "warn": SystemLogLevel.WARN,
        }

        tracing_options = {
            "active": Tracing.ACTIVE,
            "disabled": Tracing.DISABLED,
            "passthrough": Tracing.PASS_THROUGH,
        }

        # Security Hub Findings Exporter
        self.securityhub_findings_exporter = Function(
            self,
            "LambdaSecurityHubFindingsExporter",
            application_log_level_v2=app_log_level_options.get(
                lambda_vars.get("securityhub_findings_loglevel_app", None),
                SystemLogLevel.INFO,
            ),
            architecture=arch_options.get(
                lambda_vars.get("securityhub_findings_arch", None),
                Architecture.X86_64,
            ),
            code=Code.from_asset(os.path.join("lambdas", "shexporter")),
            description=lambda_vars.get(
                "securityhub_findings_description",
                "Security Hub Findings Exporter",
            ),
            environment={
                **environment_variables,
                **lambda_vars.get("function_securityhub_findings_env_vars", {}),
            },
            function_name=lambda_vars.get(
                "securityhub_findings_name",
                "securityhub-findings-exporter",
            ),
            handler=lambda_vars.get(
                "securityhub_findings_handler", "index.lambda_handler"
            ),
            logging_format=log_format_options.get(
                lambda_vars.get("securityhub_findings_logformat", None),
                LoggingFormat.JSON,
            ),
            max_event_age=Duration.hours(
                lambda_vars.get("securityhub_findings_max_event_age", 6)
            ),
            memory_size=lambda_vars.get(
                "securityhub_findings_memory_size", 128
            ),
            role=iam_stack.lambda_securityhub_findings_role,
            runtime=runtime_type.get(
                lambda_vars.get("securityhub_findings_runtime_type", None),
                Runtime.PYTHON_3_12,
            ),
            system_log_level_v2=system_log_level_options.get(
                lambda_vars.get("securityhub_findings_loglevel_sys", None),
                SystemLogLevel.INFO,
            ),
            timeout=Duration.seconds(
                lambda_vars.get("securityhub_findings_timeout", 3)
            ),
            tracing=tracing_options.get(
                lambda_vars.get("securityhub_findings_tracing_type", None),
                Tracing.DISABLED,
            ),
        )
