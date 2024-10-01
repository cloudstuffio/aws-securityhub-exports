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

        # Global Variables
        constants_vars = self.node.try_get_context("constants")
        lambda_vars = self.node.try_get_context("lambda")

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

        # Fetch Findings Function
        self.fetch_findings_function = Function(
            self,
            "FetchFindings",
            application_log_level_v2=app_log_level_options.get(
                lambda_vars.get("loglevel_app", None),
                SystemLogLevel.INFO,
            ),
            architecture=arch_options.get(
                lambda_vars.get("arch", None),
                Architecture.X86_64,
            ),
            code=Code.from_asset(os.path.join("lambdas", "fetchfindings")),
            description=constants_vars.get(
                "fetch_findings_name",
                "Security Hub Fetch Findings",
            )
            + " Function",
            environment={
                **environment_variables,
                **lambda_vars.get("env_vars", {}),
            },
            function_name=constants_vars.get(
                "fetch_findings_name",
                "securityhub-fetch-findings",
            )
            + "-function",
            handler=lambda_vars.get("handler", "index.lambda_handler"),
            logging_format=log_format_options.get(
                lambda_vars.get("logformat", None),
                LoggingFormat.JSON,
            ),
            max_event_age=Duration.hours(lambda_vars.get("max_event_age", 6)),
            memory_size=lambda_vars.get("get_function_memory_size", 128),
            role=iam_stack.lambda_fetch_findings_role,
            runtime=runtime_type.get(
                lambda_vars.get("runtime_type", None),
                Runtime.PYTHON_3_12,
            ),
            system_log_level_v2=system_log_level_options.get(
                lambda_vars.get("loglevel_sys", None),
                SystemLogLevel.INFO,
            ),
            timeout=Duration.seconds(lambda_vars.get("timeout", 3)),
            tracing=tracing_options.get(
                lambda_vars.get("tracing_type", None),
                Tracing.DISABLED,
            ),
        )

        # Generate CSV Function
        self.generate_csv_function = Function(
            self,
            "GenerateCsv",
            application_log_level_v2=app_log_level_options.get(
                lambda_vars.get("loglevel_app", None),
                SystemLogLevel.INFO,
            ),
            architecture=arch_options.get(
                lambda_vars.get("arch", None),
                Architecture.X86_64,
            ),
            code=Code.from_asset(os.path.join("lambdas", "generatecsv")),
            description=constants_vars.get(
                "generate_csv_name",
                "Security Hub Generate CSV",
            )
            + " Function",
            environment={
                **environment_variables,
                **lambda_vars.get("env_vars", {}),
            },
            function_name=constants_vars.get(
                "generate_csv_name",
                "securityhub-generate-csv",
            )
            + "-function",
            handler=lambda_vars.get("handler", "index.lambda_handler"),
            logging_format=log_format_options.get(
                lambda_vars.get("logformat", None),
                LoggingFormat.JSON,
            ),
            max_event_age=Duration.hours(lambda_vars.get("max_event_age", 6)),
            memory_size=lambda_vars.get("csv_function_memory_size", 128),
            role=iam_stack.lambda_generate_csv_role,
            runtime=runtime_type.get(
                lambda_vars.get("runtime_type", None),
                Runtime.PYTHON_3_12,
            ),
            system_log_level_v2=system_log_level_options.get(
                lambda_vars.get("loglevel_sys", None),
                SystemLogLevel.INFO,
            ),
            timeout=Duration.seconds(lambda_vars.get("timeout", 3)),
            tracing=tracing_options.get(
                lambda_vars.get("tracing_type", None),
                Tracing.DISABLED,
            ),
        )

        # Send Email Function
        self.send_email_function = Function(
            self,
            "SendEmail",
            application_log_level_v2=app_log_level_options.get(
                lambda_vars.get("loglevel_app", None),
                SystemLogLevel.INFO,
            ),
            architecture=arch_options.get(
                lambda_vars.get("arch", None),
                Architecture.X86_64,
            ),
            code=Code.from_asset(os.path.join("lambdas", "sendemail")),
            description=constants_vars.get(
                "send_email_name",
                "Security Hub Send Email",
            )
            + " Function",
            environment={
                **environment_variables,
                **lambda_vars.get("env_vars", {}),
            },
            function_name=constants_vars.get(
                "send_email_name",
                "securityhub-send-email",
            )
            + "-function",
            handler=lambda_vars.get("handler", "index.lambda_handler"),
            logging_format=log_format_options.get(
                lambda_vars.get("logformat", None),
                LoggingFormat.JSON,
            ),
            max_event_age=Duration.hours(lambda_vars.get("max_event_age", 6)),
            memory_size=lambda_vars.get("email_function_memory_size", 128),
            role=iam_stack.lambda_send_email_role,
            runtime=runtime_type.get(
                lambda_vars.get("runtime_type", None),
                Runtime.PYTHON_3_12,
            ),
            system_log_level_v2=system_log_level_options.get(
                lambda_vars.get("loglevel_sys", None),
                SystemLogLevel.INFO,
            ),
            timeout=Duration.seconds(lambda_vars.get("timeout", 3)),
            tracing=tracing_options.get(
                lambda_vars.get("tracing_type", None),
                Tracing.DISABLED,
            ),
        )
