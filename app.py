#!/usr/bin/env python3
###############################################################################
### Imports
###############################################################################
import os
import aws_cdk as cdk
from stacks.event_stack import EventStack
from stacks.iam_stack import IamStack
from stacks.lambda_stack import LambdaStack
from stacks.main_stack import MainStack
from stacks.step_stack import StepStack
from stacks.storage_stack import StorageStack


###############################################################################
### CDK App Initialization
###############################################################################
app = cdk.App()

###############################################################################
### CDK Environment
###############################################################################
account = os.getenv("CDK_DEFAULT_ACCOUNT")
region = os.getenv("CDK_DEFAULT_REGION")
stack_vars = app.node.try_get_context("stacks")

###############################################################################
### Stacks
###############################################################################
main_stack = MainStack(
    app,
    stack_vars.get("main_stack_name", "MainStack"),
    env=cdk.Environment(account=account, region=region),
)

# Nested Stacks
storage_stack = StorageStack(
    main_stack,
    stack_vars.get("storage_stack_name", "StorageStack"),
)

iam_stack = IamStack(
    main_stack,
    stack_vars.get("iam_stack_name", "IamStack"),
    storage_stack=storage_stack,
)

lambda_stack = LambdaStack(
    main_stack,
    stack_vars.get("lambda_stack_name", "LambdaStack"),
    iam_stack=iam_stack,
)

step_stack = StepStack(
    main_stack,
    stack_vars.get("step_stack_name", "StepFunctionStack"),
    iam_stack=iam_stack,
    lambda_stack=lambda_stack,
)

event_stack = EventStack(
    main_stack,
    stack_vars.get("event_stack_name", "EventStack"),
    step_stack=step_stack,
    storage_stack=storage_stack,
)

###############################################################################
### CDK App Synthesis
###############################################################################
app.synth()
