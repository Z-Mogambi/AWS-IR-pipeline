"""Environment resolution: the default must never be the permissive one."""

import pytest

from irlib import envresolve


@pytest.mark.parametrize(
    "tags,expected,source",
    [
        ([{"Key": "Environment", "Value": "Production"}], "production", "tag"),
        ([{"Key": "Environment", "Value": "prod"}], "production", "tag"),
        ([{"Key": "Environment", "Value": "dev"}], "non-production", "tag"),
        ([{"Key": "Environment", "Value": "staging"}], "non-production", "tag"),
        # EC2 tag keys are case sensitive; match loosely so a lowercase key
        # still classifies instead of falling through to the default.
        ([{"Key": "environment", "Value": "dev"}], "non-production", "tag"),
        ([{"Key": "ENVIRONMENT", "Value": "dev"}], "non-production", "tag"),
    ],
)
def test_tag_values(tags, expected, source):
    assert envresolve.resolve("111122223333", tags, account_map_raw="") == (expected, source)


def test_missing_tag_means_production():
    assert envresolve.resolve("111122223333", [], account_map_raw="") == (
        "production",
        "default-missing-tag",
    )


def test_no_tags_at_all_means_production():
    assert envresolve.resolve("111122223333", None, account_map_raw="")[0] == "production"


def test_unrecognised_tag_value_means_production():
    """An attacker who can write a tag cannot invent a value that relaxes handling."""
    environment, source = envresolve.resolve(
        "111122223333", [{"Key": "Environment", "Value": "definitely-not-prod"}], account_map_raw=""
    )
    assert environment == "production"
    assert source == "default-unknown-tag-value"


def test_account_map_overrides_the_tag():
    """Accounts are far harder to change than tags, so the map wins."""
    environment, source = envresolve.resolve(
        "111122223333",
        [{"Key": "Environment", "Value": "dev"}],
        account_map_raw="111122223333=production",
    )
    assert (environment, source) == ("production", "account-map")


def test_account_map_can_mark_an_account_non_production():
    assert envresolve.resolve(
        "444455556666", [], account_map_raw="444455556666=non-production"
    ) == ("non-production", "account-map")


def test_account_not_in_the_map_falls_through_to_tags():
    assert envresolve.resolve(
        "999988887777",
        [{"Key": "Environment", "Value": "dev"}],
        account_map_raw="111122223333=production",
    ) == ("non-production", "tag")


@pytest.mark.parametrize(
    "raw",
    ["garbage", "111122223333=banana", "=production", "111122223333", ""],
)
def test_malformed_account_map_entries_are_ignored_not_guessed(raw):
    assert envresolve.parse_account_map(raw) == {}


def test_account_map_parses_whitespace_and_multiple_entries():
    assert envresolve.parse_account_map(
        " 111122223333=production , 444455556666=non-production "
    ) == {"111122223333": "production", "444455556666": "non-production"}
