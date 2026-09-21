"""Call an AWS API that the bundled SDK does not model yet.

GuardDuty's CreateInvestigation is in preview and is absent from the boto3
shipped in the Lambda runtime (confirmed: 1.42.33 has no create_investigation;
it appears around 1.43.98). Rather than vendor a second copy of boto3 into one
function - which would break the no-third-party-runtime-dependency rule and add
roughly 15 MB to the package - the request is signed directly with botocore's
own SigV4 machinery, which is already there.

This is deliberately minimal: one signed JSON request, no retries beyond the
caller's, and no attempt to be a general-purpose client.
"""

import json
import logging
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

logger = logging.getLogger()

DEFAULT_TIMEOUT_SECONDS = 20


def signed_request(service, region, method, url, payload=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    """Sign and send one request. Returns (status_code, parsed_body_or_text)."""
    body = json.dumps(payload or {}) if method in ("POST", "PUT", "PATCH") else ""
    request = AWSRequest(
        method=method,
        url=url,
        data=body,
        headers={"Content-Type": "application/json"},
    )

    credentials = boto3.Session().get_credentials()
    if credentials is None:
        raise RuntimeError("No credentials available to sign the request")
    SigV4Auth(credentials.get_frozen_credentials(), service, region).add_auth(request)

    urllib_request = urllib.request.Request(
        url, data=body.encode("utf-8") if body else None, method=method
    )
    for header, value in request.headers.items():
        urllib_request.add_header(header, value)

    try:
        with urllib.request.urlopen(urllib_request, timeout=timeout) as response:
            return response.status, _parse(response.read())
    except urllib.error.HTTPError as error:
        return error.code, _parse(error.read())


def _parse(raw):
    text = (raw or b"").decode("utf-8", "replace")
    try:
        return json.loads(text) if text else {}
    except ValueError:
        return {"raw": text[:2000]}
