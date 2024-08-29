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
iam_stack = IamStack(
    main_stack,
    stack_vars.get("iam_stack_name", "IamStack"),
)

lambda_stack = LambdaStack(
    main_stack,
    stack_vars.get("lambda_stack_name", "LambdaStack"),
    iam_stack=iam_stack,
)

event_stack = EventStack(
    main_stack,
    stack_vars.get("event_stack_name", "EventStack"),
    lambda_stack=lambda_stack,
)

###############################################################################
### CDK App Synthesis
###############################################################################
app.synth()
