import json
import os
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sfn_client = boto3.client('stepfunctions')
STATE_MACHINE_ARN = os.environ['SFN_STATE_MACHINE_ARN']

def handler(event, context):
    """
    Handles GuardDuty findings from EventBridge, starts the Step Function execution.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # Extract instance ID from GuardDuty finding
    try:
        instance_id = event['detail']['resource']['instanceDetails']['instanceId']
    except KeyError:
        logger.error("Could not find instanceId in the event.")
        return

    sfn_input = {
        'GuardDutyFinding': event['detail'],
        'InstanceId': instance_id
    }

    try:
        response = sfn_client.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            input=json.dumps(sfn_input)
        )
        logger.info(f"Started Step Function execution: {response['executionArn']}")
    except Exception as e:
        logger.error(f"Error starting Step Function execution: {e}")
        raise

    return {
        'statusCode': 200,
        'body': json.dumps('Step Function execution started successfully.')
    }