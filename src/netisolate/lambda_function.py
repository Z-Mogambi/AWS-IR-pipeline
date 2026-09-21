"""Network isolation that actually severs the attacker's session.

Swapping an instance to a security group with no rules does not close
connections the VPC is already tracking, so an established reverse shell
survives it. The documented way to break those flows is to make them
*untracked* first: attach a group that allows all traffic in and out, which
stops the VPC tracking them, then revoke those rules, which drops untracked
flows immediately.

That means the instance is briefly wide open. The window is measured in
seconds, is bracketed by the two ledger records `quarantine-sg-open` and
`quarantine-sg-seal`, and both timestamps are returned so the exposure is
auditable rather than assumed.

Two other things this fixes over the previous implementation:

* the quarantine group is created per incident and tagged with the incident id.
  A shared group meant two concurrent incidents raced on it, and opening it for
  one instance briefly un-isolated every other instance behind it.
* every ENI is moved with ModifyNetworkInterfaceAttribute.
  ModifyInstanceAttribute(Groups=...) only moves the primary interface, so a
  multi-ENI instance stayed reachable on its others.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from irlib import incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
route53resolver_client = boto3.client("route53resolver")

ENABLE_NACL_BACKSTOP = os.environ.get("ENABLE_NACL_BACKSTOP", "false").lower() == "true"
DNS_FIREWALL_DOMAIN_LIST_ID = os.environ.get("DNS_FIREWALL_DOMAIN_LIST_ID", "")
DNS_FIREWALL_RULE_GROUP_ID = os.environ.get("DNS_FIREWALL_RULE_GROUP_ID", "")
DNS_FIREWALL_PRIORITY = int(os.environ.get("DNS_FIREWALL_PRIORITY", "101"))

# Allow every protocol from and to anywhere, v4 and v6. Attaching this is what
# converts tracked connections into untracked ones.
ALLOW_ALL = [
    {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
]

# NACL rules are evaluated lowest number first, so the backstop needs low
# numbers to win. This range is reserved for the pipeline; entries outside it
# are never touched.
NACL_RULE_RANGE = range(1, 51)


def handler(event, context):
    logger.info(f"Isolating network: {json.dumps(event)}")

    incident_id = event["incidentId"]
    instance = (event.get("enrichment") or {}).get("instance") or {}
    targets = (event.get("finding") or {}).get("targets") or {}

    instance_id = instance.get("instanceId")
    vpc_id = instance.get("vpcId")
    if not instance_id:
        raise ValueError("No instance to isolate; Decide should have downgraded this.")
    if not vpc_id:
        raise ValueError(f"No VPC for {instance_id}; cannot place a quarantine group.")

    interfaces = instance.get("networkInterfaces") or []
    if not interfaces:
        raise ValueError(f"No network interfaces recorded for {instance_id}.")

    performed = []

    def step(key, action, target, perform, prior_state=None, best_effort=False):
        result = incidents.run_action(
            incident_id, key, action, target, perform,
            prior_state=prior_state, best_effort=best_effort,
        )
        performed.append(result)
        return result

    # 1. A group of this incident's own, so nothing else is affected by what
    #    happens to it next.
    created = step(
        f"quarantine-sg-create#{incident_id}", "quarantine-sg-create", vpc_id,
        lambda prior: create_quarantine_group(incident_id, vpc_id),
    )
    quarantine_sg_id = (created.get("result") or {}).get("groupId")
    if not quarantine_sg_id:
        quarantine_sg_id = find_quarantine_group(incident_id, vpc_id)
    if not quarantine_sg_id:
        raise RuntimeError(f"Could not resolve the quarantine group for incident {incident_id}")

    # 2. Open it wide. This is the deliberate, brief exposure.
    step(
        f"quarantine-sg-open#{incident_id}", "quarantine-sg-open", quarantine_sg_id,
        lambda prior: open_all_traffic(quarantine_sg_id),
    )

    # 3. Move every interface onto it, recording what each one had.
    for interface in interfaces:
        eni_id = interface.get("networkInterfaceId")
        if not eni_id:
            continue
        step(
            f"eni-isolate#{eni_id}", "eni-isolate", eni_id,
            lambda prior, eni=eni_id: attach_quarantine(eni, quarantine_sg_id),
            prior_state={"groups": interface.get("groups") or [], "instanceId": instance_id},
        )

    # 4. Close it. Flows that became untracked in step 2 die here.
    sealed = step(
        f"quarantine-sg-seal#{incident_id}", "quarantine-sg-seal", quarantine_sg_id,
        lambda prior: seal_group(quarantine_sg_id),
    )

    # 5. Optional extras, neither of which may block the isolation above.
    if ENABLE_NACL_BACKSTOP and targets.get("remoteIps"):
        step(
            f"nacl-backstop#{instance_id}", "nacl-backstop", instance.get("subnetId") or "",
            lambda prior: nacl_backstop(instance.get("subnetId"), targets["remoteIps"]),
            best_effort=True,
        )

    if targets.get("domains") and DNS_FIREWALL_DOMAIN_LIST_ID:
        step(
            f"dns-block#{incident_id}", "dns-block", ",".join(targets["domains"]),
            lambda prior: block_domains(vpc_id, targets["domains"]),
            best_effort=True,
        )

    window = exposure_window(created, sealed, performed)
    logger.info(
        f"Isolated {instance_id} across {len(interfaces)} interface(s) behind "
        f"{quarantine_sg_id}; open for {window.get('seconds')}s"
    )
    return {
        "actions": performed,
        "instanceId": instance_id,
        "quarantineSecurityGroupId": quarantine_sg_id,
        "interfacesIsolated": [i.get("networkInterfaceId") for i in interfaces],
        "exposureWindow": window,
    }


# --- security group ---------------------------------------------------------


def quarantine_group_name(incident_id):
    # Security group names are capped at 255 characters.
    return f"ir-quarantine-{incident_id}"[:255]


def find_quarantine_group(incident_id, vpc_id):
    response = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "tag:IRPipeline:IncidentId", "Values": [incident_id]},
        ]
    )
    groups = response.get("SecurityGroups") or []
    return groups[0]["GroupId"] if groups else None


def create_quarantine_group(incident_id, vpc_id):
    """One group per incident, tagged so release can find and delete it."""
    existing = find_quarantine_group(incident_id, vpc_id)
    if existing:
        logger.info(f"Reusing quarantine group {existing} for incident {incident_id}")
        return {"groupId": existing, "created": False}

    response = ec2_client.create_security_group(
        GroupName=quarantine_group_name(incident_id),
        Description=f"IR quarantine for incident {incident_id}",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": "IRPipeline:IncidentId", "Value": incident_id},
                    {"Key": "IRPipeline:Role", "Value": "quarantine"},
                ],
            }
        ],
    )
    group_id = response["GroupId"]
    # New groups are eventually consistent; wait before anything describes it.
    ec2_client.get_waiter("security_group_exists").wait(GroupIds=[group_id])
    return {"groupId": group_id, "created": True}


def open_all_traffic(group_id):
    """Allow everything, so existing flows stop being tracked.

    A new group already permits all egress to 0.0.0.0/0, so the egress
    authorisation can collide with that default. A duplicate here means the
    rule is already in place, which is the state we want.
    """
    opened_at = datetime.now(timezone.utc).isoformat()
    for authorize in (
        ec2_client.authorize_security_group_ingress,
        ec2_client.authorize_security_group_egress,
    ):
        try:
            authorize(GroupId=group_id, IpPermissions=ALLOW_ALL)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                raise
    return {"openedAt": opened_at, "groupId": group_id}


def attach_quarantine(eni_id, quarantine_sg_id):
    """Move one interface. Per-ENI, because the instance-level call misses secondaries."""
    ec2_client.modify_network_interface_attribute(
        NetworkInterfaceId=eni_id, Groups=[quarantine_sg_id]
    )
    return {"networkInterfaceId": eni_id, "groups": [quarantine_sg_id]}


def seal_group(group_id):
    """Revoke everything. Untracked flows are dropped the moment this lands."""
    groups = ec2_client.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    group = groups[0]
    if group.get("IpPermissions"):
        ec2_client.revoke_security_group_ingress(
            GroupId=group_id, IpPermissions=group["IpPermissions"]
        )
    if group.get("IpPermissionsEgress"):
        ec2_client.revoke_security_group_egress(
            GroupId=group_id, IpPermissions=group["IpPermissionsEgress"]
        )
    return {"sealedAt": datetime.now(timezone.utc).isoformat(), "groupId": group_id}


def exposure_window(created, sealed, performed):
    """How long the instance was open, from the ledger's own timestamps."""
    opened_at = None
    for entry in performed:
        if entry["action"] == "quarantine-sg-open":
            opened_at = (entry.get("result") or {}).get("openedAt")
    sealed_at = (sealed.get("result") or {}).get("sealedAt")
    if not opened_at or not sealed_at:
        return {"openedAt": opened_at, "sealedAt": sealed_at, "seconds": None}

    start = datetime.fromisoformat(opened_at)
    end = datetime.fromisoformat(sealed_at)
    return {
        "openedAt": opened_at,
        "sealedAt": sealed_at,
        "seconds": round((end - start).total_seconds(), 3),
    }


# --- NACL backstop ----------------------------------------------------------


def nacl_backstop(subnet_id, remote_ips):
    """Stateless deny entries for the remote addresses named in the finding.

    NACLs are stateless, so a deny takes effect on established connections
    immediately - useful as a second line if the security group work is
    somehow undone. The rule numbers come from a range reserved for this
    pipeline; if none are free the step is skipped rather than overwriting
    someone else's rule.
    """
    if not subnet_id:
        return {"skipped": "no subnet id"}

    acls = ec2_client.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    ).get("NetworkAcls") or []
    if not acls:
        return {"skipped": f"no network ACL found for {subnet_id}"}

    acl = acls[0]
    acl_id = acl["NetworkAclId"]
    used = {entry["RuleNumber"] for entry in acl.get("Entries", [])}
    free = [n for n in NACL_RULE_RANGE if n not in used]

    entries, skipped = [], []
    for ip in remote_ips:
        cidr = f"{ip}/32"
        for egress in (False, True):
            if not free:
                skipped.append({"cidr": cidr, "egress": egress, "reason": "no free rule number"})
                continue
            rule_number = free.pop(0)
            ec2_client.create_network_acl_entry(
                NetworkAclId=acl_id,
                RuleNumber=rule_number,
                Protocol="-1",
                RuleAction="deny",
                Egress=egress,
                CidrBlock=cidr,
            )
            entries.append({"networkAclId": acl_id, "ruleNumber": rule_number, "egress": egress,
                            "cidrBlock": cidr})

    return {"networkAclId": acl_id, "entries": entries, "skipped": skipped}


# --- DNS Firewall -----------------------------------------------------------


def block_domains(vpc_id, domains):
    """Add the queried domains to the block list and make sure it applies here.

    Security groups do not filter DNS to the Route 53 Resolver, so a
    DNS-tunnelled channel survives everything above. This is the only control
    that closes it - and it is VPC-wide, not instance-scoped, which is a real
    limitation worth stating in the notification.
    """
    normalised = sorted({d.rstrip(".").lower() for d in domains if d})
    route53resolver_client.update_firewall_domains(
        FirewallDomainListId=DNS_FIREWALL_DOMAIN_LIST_ID,
        Operation="ADD",
        Domains=normalised,
    )

    association_id = ensure_vpc_association(vpc_id)
    return {
        "domains": normalised,
        "domainListId": DNS_FIREWALL_DOMAIN_LIST_ID,
        "associationId": association_id,
        "scope": "vpc-wide",
    }


def ensure_vpc_association(vpc_id):
    """Associate the block rule group with the VPC if it is not already."""
    if not DNS_FIREWALL_RULE_GROUP_ID:
        return None

    existing = route53resolver_client.list_firewall_rule_group_associations(
        FirewallRuleGroupId=DNS_FIREWALL_RULE_GROUP_ID, VpcId=vpc_id
    ).get("FirewallRuleGroupAssociations") or []
    if existing:
        return existing[0].get("Id")

    response = route53resolver_client.associate_firewall_rule_group(
        FirewallRuleGroupId=DNS_FIREWALL_RULE_GROUP_ID,
        VpcId=vpc_id,
        Priority=DNS_FIREWALL_PRIORITY,
        Name=f"ir-quarantine-{vpc_id}"[:64],
        CreatorRequestId=f"ir-{vpc_id}"[:255],
    )
    return (response.get("FirewallRuleGroupAssociation") or {}).get("Id")
