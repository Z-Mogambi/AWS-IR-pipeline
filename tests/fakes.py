"""A recording fake for the incident ledger.

The containment tests care about *ordering* - that the write-ahead record lands
before the mutating call - so every client shares one call log.
"""

import json

from botocore.exceptions import ClientError

from irlib import incidents


class LedgerFake:
    """Accepts ledger writes, optionally reporting some actions already done."""

    def __init__(self, log, completed=None):
        self.log = log
        self.completed = completed or {}

    def put_item(self, **kwargs):
        record_id = kwargs["Item"]["RecordId"]["S"]
        self.log.append(("ledger.put_item", kwargs))
        if record_id in self.completed:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "exists"}},
                "PutItem",
            )
        return {}

    def get_item(self, **kwargs):
        record_id = kwargs["Key"]["RecordId"]["S"]
        self.log.append(("ledger.get_item", kwargs))
        payload = self.completed.get(record_id)
        if payload is None:
            return {}
        return {
            "Item": {
                "RecordId": {"S": record_id},
                "Status": {"S": incidents.STATUS_DONE},
                "Result": {"S": json.dumps(payload)},
            }
        }

    def update_item(self, **kwargs):
        self.log.append(("ledger.update_item", kwargs))
        return {}


class ServiceFake:
    """Records every call and returns canned responses by operation name."""

    def __init__(self, log, prefix, responses=None, errors=None):
        self.log = log
        self.prefix = prefix
        self.responses = responses or {}
        self.errors = errors or {}

    def __getattr__(self, name):
        def call(**kwargs):
            self.log.append((f"{self.prefix}.{name}", kwargs))
            if name in self.errors:
                raise self.errors[name]
            value = self.responses.get(name, {})
            return value(kwargs) if callable(value) else value

        return call

    def get_waiter(self, _name):
        class Waiter:
            def wait(self, **kwargs):
                return None

        return Waiter()


def names(log):
    return [entry[0] for entry in log]


def params(log, operation):
    return [entry[1] for entry in log if entry[0] == operation]


def ledger_writes(log):
    """The action keys written ahead, in order."""
    return [
        entry[1]["Item"]["RecordId"]["S"].removeprefix(incidents.ACTION_PREFIX)
        for entry in log
        if entry[0] == "ledger.put_item"
        and entry[1]["Item"]["RecordId"]["S"].startswith(incidents.ACTION_PREFIX)
    ]
