"""Tests for `latte.admin.AdminClient` against a mocked admin API
(`responses`): every method's verb, path, auth header, body and query,
204/202 handling, and error mapping."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest
import requests
import responses

from latte import errors
from latte.admin import UNSET, AdminClient, AdminError, License

BASE = "https://api.test/v1"
LIC: dict[str, Any] = {
    "id": "i",
    "project_id": "p",
    "policy_id": "pol",
    "license_key": "AB-CD",
    "status": "suspended",
    "expires_at": None,
    "metadata": {"a": 1},
    "client_metadata": {},
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
    "future_field": {"x": True},
}


@pytest.fixture
def client() -> AdminClient:
    return AdminClient("llk_test_secret", base_url=BASE + "/")


def last() -> requests.PreparedRequest:
    return responses.calls[-1].request


def body() -> Any:
    raw = last().body
    return json.loads(raw) if raw else None


def check(method: str, url: str) -> None:
    req = last()
    assert req.method == method
    assert (req.url or "").split("?")[0] == BASE + url
    assert req.headers["Authorization"] == "Bearer llk_test_secret"


def test_requires_api_key() -> None:
    with pytest.raises(ValueError):
        AdminClient("")


@responses.activate
def test_issue_license(client: AdminClient) -> None:
    responses.post(BASE + "/licenses", json=LIC, status=201)
    lic = client.issue_license("pol", customer_email="b@example.com", metadata={"order": "1"})
    check("POST", "/licenses")
    assert body() == {
        "policy_id": "pol",
        "customer_email": "b@example.com",
        "metadata": {"order": "1"},
    }
    assert isinstance(lic, License)
    assert lic.license_key == "AB-CD" and lic.status == "suspended" and lic.expires_at is None
    assert lic.raw["future_field"] == {"x": True}


@responses.activate
def test_list_licenses_query(client: AdminClient) -> None:
    responses.get(BASE + "/licenses", json={"licenses": [LIC], "total": 7})
    page = client.list_licenses(
        limit=10, offset=20, customer_email="a+b@example.com", status="active"
    )
    check("GET", "/licenses")
    url = last().url or ""
    assert "limit=10" in url and "offset=20" in url and "status=active" in url
    assert "customer_email=a%2Bb%40example.com" in url
    assert page.total == 7 and page.licenses[0].id == "i"
    client.list_licenses()
    assert "?" not in (last().url or "")


@responses.activate
def test_get_license_escapes_key(client: AdminClient) -> None:
    responses.get(BASE + "/licenses/AB%2FCD%20EF", json=LIC)
    client.get_license("AB/CD EF")
    assert last().url == BASE + "/licenses/AB%2FCD%20EF"


@responses.activate
def test_update_license_bodies(client: AdminClient) -> None:
    responses.patch(BASE + "/licenses/K", json=LIC)
    client.update_license("K", metadata={"a": 1}, client_metadata={})
    check("PATCH", "/licenses/K")
    assert body() == {"metadata": {"a": 1}, "client_metadata": {}}
    client.update_license("K", expires_at=datetime(2027, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    assert body() == {"expires_at": "2027-01-02T03:04:05+00:00"}
    client.update_license("K", expires_at=None)
    assert body() == {"expires_at": None}
    client.update_license("K")
    assert body() == {}


@responses.activate
def test_revoke_and_release_204(client: AdminClient) -> None:
    responses.delete(BASE + "/licenses/K", status=204)
    responses.delete(BASE + "/licenses/K/activations/act-1", status=204)
    assert client.revoke_license("K") is None
    check("DELETE", "/licenses/K")
    assert client.release_activation("K", "act-1") is None
    check("DELETE", "/licenses/K/activations/act-1")
    assert last().body is None


@responses.activate
def test_suspend_and_reinstate(client: AdminClient) -> None:
    responses.post(BASE + "/licenses/K/suspend", json=LIC)
    responses.post(BASE + "/licenses/K/reinstate", json=LIC)
    assert client.suspend_license("K").id == "i"
    check("POST", "/licenses/K/suspend")
    client.reinstate_license("K")
    check("POST", "/licenses/K/reinstate")


@responses.activate
def test_resend_202(client: AdminClient) -> None:
    responses.post(BASE + "/licenses/K/resend", json={"status": "queued"}, status=202)
    assert client.resend_license_email("K") is None
    check("POST", "/licenses/K/resend")


@responses.activate
def test_list_activations(client: AdminClient) -> None:
    act = {
        "id": "a1",
        "status": "active",
        "machine_id_hash": "h",
        "activated_at": "2026-01-01T00:00:00Z",
        "last_renewed_at": None,
        "deactivated_at": None,
        "seat_held_until": None,
        "sdk": {"language": "go"},
        "metadata": {},
        "extra": 1,
    }
    responses.get(BASE + "/licenses/K/activations", json={"activations": [act]})
    a = client.list_activations("K")[0]
    check("GET", "/licenses/K/activations")
    assert a.id == "a1" and a.last_renewed_at is None and a.raw["extra"] == 1


@responses.activate
def test_list_policies(client: AdminClient) -> None:
    pol = {
        "id": "p1",
        "name": "Pro",
        "license_type": "expiring",
        "expiry_mode": "from_issuance",
        "expiry_date": None,
        "expiry_days": 365,
        "max_activations": None,
        "grace_period_hours": 168,
        "created_at": "2026-03-04T11:20:41.882Z",
    }
    responses.get(BASE + "/policies", json={"policies": [pol]})
    p = client.list_policies()[0]
    check("GET", "/policies")
    assert p.expiry_days == 365 and p.max_activations is None


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 429])
@responses.activate
def test_error_mapping(client: AdminClient, status: int) -> None:
    responses.get(
        BASE + "/licenses/K",
        json={"error": "nope", "code": "plan_license_limit_reached"},
        status=status,
    )
    with pytest.raises(AdminError) as ei:
        client.get_license("K")
    e = ei.value
    assert (
        e.status_code == status and e.message == "nope" and e.code == "plan_license_limit_reached"
    )
    assert isinstance(e, errors.LatteError)


@responses.activate
def test_non_json_error_falls_back_to_reason(client: AdminClient) -> None:
    responses.delete(BASE + "/licenses/K", body="<html>", status=502)
    with pytest.raises(AdminError) as ei:
        client.revoke_license("K")
    assert ei.value.status_code == 502 and ei.value.message == "Bad Gateway"


@responses.activate
def test_transport_failure_is_network_error(client: AdminClient) -> None:
    responses.get(BASE + "/policies", body=requests.ConnectionError("boom"))
    with pytest.raises(errors.NetworkError):
        client.list_policies()


@responses.activate
def test_write_is_not_retried(client: AdminClient) -> None:
    responses.post(BASE + "/licenses", json={"error": "slow down"}, status=429)
    with pytest.raises(AdminError):
        client.issue_license("p")
    assert len(responses.calls) == 1


@responses.activate
def test_default_base_url_and_timeout() -> None:
    responses.get("https://api.licenselatte.com/v1/policies", json={"policies": []})
    assert AdminClient("k", timeout=5).list_policies() == []


def test_unset_repr() -> None:
    assert repr(UNSET) == "UNSET"
