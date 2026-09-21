"""Shared, dependency-free helpers for the incident response pipeline.

Everything in here must run on the standard library plus the boto3/botocore
already bundled in the Lambda runtime. This package is published as a Lambda
layer, so a third-party import would have to be vendored into every function.
"""
