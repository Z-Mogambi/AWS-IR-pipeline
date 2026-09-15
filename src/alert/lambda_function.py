import json
import os
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns_client = boto3.client('sns')
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

def handler(event, context):
    """
    Sends an alert about the security finding via SNS.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    instance_id = event['InstanceId']
    is_production = event['IsProduction']
    finding = event['GuardDutyFinding']

    severity = finding.get('severity', 'UNKNOWN')
    finding_type = finding.get('type', 'UNKNOWN')
    finding_description = finding.get('description', 'No description.')

    subject = f"Security Alert: GuardDuty finding for EC2 {'PROD' if is_production else 'NON-PROD'} instance {instance_id}"

    message = f"""
    A security finding has been detected by GuardDuty.

    Instance ID: {instance_id}
    Environment: {'Production' if is_production else 'Non-Production'}

    Finding Type: {finding_type}
    Severity: {severity}
    Description: {finding_description}

    The instance has been automatically isolated if it was a production instance. Please investigate immediately.

    Full finding details:
    {json.dumps(finding, indent=2)}
    """

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        logger.info(f"Successfully sent alert for instance {instance_id}")

        return {
            'AlertResult': {
                'Status': 'ALERT_SENT'
            }
        }
    except Exception as e:
        logger.error(f"Error sending SNS alert for instance {instance_id}: {e}")
        raise