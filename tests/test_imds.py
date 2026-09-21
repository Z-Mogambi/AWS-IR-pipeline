"""Disabling IMDS: last, and reversible."""

import json

import pytest

from conftest import load_lambda
from fakes import LedgerFake, ServiceFake, names, params
from irlib import incidents

imds = load_lambda("imds")

PRIOR = {
    "HttpEndpoint": "enabled",
    "HttpTokens": "required",
    "HttpPutResponseHopLimit": 2,
    "InstanceMetadataTags": "enabled",
    "HttpProtocolIpv6": "disabled",
}


def build_event(metadata_options=None, instance_id="i-0123456789abcdef0"):
    return {
        "incidentId": "inc-1",
        "enrichment": {
            "instance": {
                "instanceId": instance_id,
                "metadataOptions": PRIOR if metadata_options is None else metadata_options,
            }
        },
    }


@pytest.fixture
def wired(monkeypatch):
    log = []

    def configure(completed=None):
        monkeypatch.setattr(incidents, "_client", lambda c=None: LedgerFake(log, completed))
        monkeypatch.setattr(imds, "ec2_client", ServiceFake(log, "ec2", responses={
            "modify_instance_metadata_options": {"InstanceMetadataOptions": {"HttpEndpoint": "disabled"}}
        }))
        return log

    return log, configure


def test_the_endpoint_is_disabled(wired):
    log, configure = wired
    configure()
    imds.handler(build_event(), None)
    assert params(log, "ec2.modify_instance_metadata_options")[0] == {
        "InstanceId": "i-0123456789abcdef0",
        "HttpEndpoint": "disabled",
    }


def test_every_prior_setting_is_recorded(wired):
    """Restoring HttpTokens matters: putting 'required' back as 'optional'
    would silently weaken the instance against SSRF."""
    log, configure = wired
    configure()
    imds.handler(build_event(), None)

    record = [e for e in log if e[0] == "ledger.put_item"][0][1]
    prior = json.loads(record["Item"]["PriorState"]["S"])
    assert prior == {
        "httpEndpoint": "enabled",
        "httpTokens": "required",
        "httpPutResponseHopLimit": 2,
        "instanceMetadataTags": "enabled",
        "httpProtocolIpv6": "disabled",
    }


def test_prior_state_is_recorded_before_the_change(wired):
    log, configure = wired
    configure()
    imds.handler(build_event(), None)
    order = names(log)
    assert order.index("ledger.put_item") < order.index("ec2.modify_instance_metadata_options")


def test_no_instance_is_not_an_error(wired):
    log, configure = wired
    configure()
    result = imds.handler({"incidentId": "inc-1", "enrichment": {"instance": {}}}, None)
    assert result["actions"] == []
    assert "ec2.modify_instance_metadata_options" not in names(log)


def test_a_repeat_run_does_not_disable_twice(wired):
    log, configure = wired
    configure(completed={"ACTION#disable-imds#i-0123456789abcdef0": {"httpEndpoint": "disabled"}})
    imds.handler(build_event(), None)
    assert "ec2.modify_instance_metadata_options" not in names(log)


def test_missing_metadata_options_still_records_a_placeholder(wired):
    """An instance described before the field existed must not break release."""
    log, configure = wired
    configure()
    imds.handler(build_event(metadata_options={}), None)
    record = [e for e in log if e[0] == "ledger.put_item"][0][1]
    prior = json.loads(record["Item"]["PriorState"]["S"])
    assert set(prior) == {"httpEndpoint", "httpTokens", "httpPutResponseHopLimit",
                          "instanceMetadataTags", "httpProtocolIpv6"}
    assert all(value is None for value in prior.values())
