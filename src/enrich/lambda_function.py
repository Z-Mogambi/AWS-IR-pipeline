import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2')

def handler(event, context):
    """
    Enriches the finding with EC2 metadata.
    Checks if the instance has a 'Production' environment tag.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    instance_id = event['InstanceId']

    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if not response['Reservations'] or not response['Reservations'][0]['Instances']:
            raise ValueError(f"Instance {instance_id} not found.")

        # boto3 returns datetime objects (e.g. LaunchTime) that aren't JSON serializable,
        # which would break both the log line below and the Step Functions task output
        instance_details = json.loads(json.dumps(response['Reservations'][0]['Instances'][0], default=str))

        is_production = False
        if 'Tags' in instance_details:
            for tag in instance_details['Tags']:
                if tag.get('Key') == 'Environment' and tag.get('Value') == 'Production':
                    is_production = True
                    break

        enriched_data = {
            'InstanceId': instance_id,
            'VpcId': instance_details.get('VpcId'),
            'IsProduction': is_production,
            'InstanceDetails': instance_details,
            'GuardDutyFinding': event['GuardDutyFinding']
        }

        logger.info(f"Enrichment complete: {json.dumps(enriched_data)}")
        return enriched_data

    except Exception as e:
        logger.error(f"Error describing instance {instance_id}: {e}")
        raise