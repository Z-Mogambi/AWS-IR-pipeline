"""Disable the instance metadata endpoint. Always the last containment step.

Turning off IMDS stops the instance minting fresh role credentials, which is
what makes the credential Deny stick rather than being outrun by a new session.

It runs last because it also cuts off the SSM agent, which needs IMDS to get
credentials. Once this lands, nothing can be run on the instance remotely -
so anything that needs the agent has to have happened already.

The prior settings are recorded first. Restoring them on release matters:
putting `HttpTokens` back to `optional` when it was `required` would silently
weaken the instance against SSRF.
"""

import json
import logging

import boto3

from irlib import incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")


def handler(event, context):
    logger.info(f"Disabling IMDS: {json.dumps(event)}")

    incident_id = event["incidentId"]
    instance = (event.get("enrichment") or {}).get("instance") or {}
    instance_id = instance.get("instanceId")
    if not instance_id:
        logger.info("No instance to disable IMDS on.")
        return {"actions": [], "skipped": "no instance"}

    prior = instance.get("metadataOptions") or {}

    def perform(recorded):
        response = ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id, HttpEndpoint="disabled"
        )
        return {
            "instanceId": instance_id,
            "httpEndpoint": "disabled",
            "applied": (response.get("InstanceMetadataOptions") or {}).get("HttpEndpoint"),
        }

    result = incidents.run_action(
        incident_id,
        f"disable-imds#{instance_id}",
        "disable-imds",
        instance_id,
        perform,
        # Everything release needs to put the endpoint back exactly as it was.
        prior_state={
            "httpEndpoint": prior.get("HttpEndpoint"),
            "httpTokens": prior.get("HttpTokens"),
            "httpPutResponseHopLimit": prior.get("HttpPutResponseHopLimit"),
            "instanceMetadataTags": prior.get("InstanceMetadataTags"),
            "httpProtocolIpv6": prior.get("HttpProtocolIpv6"),
        },
    )

    logger.info(f"IMDS disabled on {instance_id}; the SSM agent is now cut off too.")
    return {"actions": [result], "instanceId": instance_id}
