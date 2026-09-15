import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2')
QUARANTINE_SG_NAME = 'quarantine-sg'

def handler(event, context):
    """
    Isolates the EC2 instance by attaching a quarantine security group.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    instance_id = event['InstanceId']
    vpc_id = event['VpcId']

    if not vpc_id:
        logger.error(f"VpcId not found for instance {instance_id}. Cannot proceed with isolation.")
        raise ValueError("VpcId is required for isolation.")

    try:
        # Check if quarantine SG exists, create if not
        try:
            response = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [QUARANTINE_SG_NAME]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            if response['SecurityGroups']:
                quarantine_sg = response['SecurityGroups'][0]
                logger.info(f"Quarantine SG '{QUARANTINE_SG_NAME}' already exists with ID: {quarantine_sg['GroupId']}")
            else:
                sg_response = ec2_client.create_security_group(
                    GroupName=QUARANTINE_SG_NAME,
                    Description='For isolating compromised instances. No ingress/egress.',
                    VpcId=vpc_id
                )
                # New SGs are eventually consistent, so wait until it's visible before describing it
                ec2_client.get_waiter('security_group_exists').wait(GroupIds=[sg_response['GroupId']])
                quarantine_sg = ec2_client.describe_security_groups(GroupIds=[sg_response['GroupId']])['SecurityGroups'][0]
                logger.info(f"Created quarantine SG '{QUARANTINE_SG_NAME}' with ID: {quarantine_sg['GroupId']}")

            quarantine_sg_id = quarantine_sg['GroupId']

            # AWS adds an allow-all egress rule to every new SG. Revoke all egress so the
            # isolated instance can't reach out (e.g. to a C2 server or for exfiltration)
            if quarantine_sg['IpPermissionsEgress']:
                ec2_client.revoke_security_group_egress(
                    GroupId=quarantine_sg_id,
                    IpPermissions=quarantine_sg['IpPermissionsEgress']
                )
                logger.info(f"Revoked all egress rules on quarantine SG {quarantine_sg_id}")
        except Exception as e:
            logger.error(f"Error preparing quarantine security group: {e}")
            raise

        # Isolate instance by replacing its SGs with the quarantine SG
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[quarantine_sg_id]
        )
        logger.info(f"Successfully isolated instance {instance_id} with SG {quarantine_sg_id}")

        return {
            'IsolationResult': {
                'InstanceId': instance_id,
                'Status': 'ISOLATED',
                'SecurityGroupId': quarantine_sg_id
            }
        }
    except Exception as e:
        logger.error(f"Error isolating instance {instance_id}: {e}")
        raise