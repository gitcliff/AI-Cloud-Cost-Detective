"""IAM collectors against stubbed AWS responses."""

import json
from urllib.parse import quote

import pytest

from governance import iam_collectors
from governance.collectors import run_collector
from governance.models import CollectorStatus
from tests.governance.test_collectors import ACCOUNT, REGION, StubSession

CSV = (
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,"
    "mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,"
    "access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,"
    "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
    "<root_account>,arn:aws:iam::111122223333:root,2020-01-01T00:00:00+00:00,not_supported,"
    "2026-01-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,"
    "false,N/A,false,N/A\n"
    "alice,arn:aws:iam::111122223333:user/alice,2024-01-01T00:00:00+00:00,true,"
    "2026-11-01T00:00:00+00:00,N/A,N/A,false,true,2026-10-14T00:00:00+00:00,2026-11-11T00:00:00+00:00,"
    "us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"
)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    calls = []
    monkeypatch.setattr(iam_collectors, "_sleep", calls.append)
    return calls


def test_credential_report_polls_until_complete_and_keeps_only_needed_fields(no_sleep):
    s = StubSession()
    st = s.stub("iam")
    st.add_response("generate_credential_report", {"State": "STARTED"}, {})
    st.add_response("generate_credential_report", {"State": "INPROGRESS"}, {})
    st.add_response("generate_credential_report", {"State": "COMPLETE"}, {})
    st.add_response("get_credential_report", {"Content": CSV.encode(), "ReportFormat": "text/csv"}, {})
    result = run_collector("iam_credential_report", iam_collectors.collect_credential_report, s, REGION, ACCOUNT)
    assert result.ok
    assert no_sleep == [1.0, 2.0]
    alice = result.items[1]
    assert alice["mfa_active"] == "false"
    assert "access_key_1_last_used_service" not in alice  # raw CSV fields not needed are dropped
    st.assert_no_pending_responses()


def test_credential_report_never_ready_times_out():
    s = StubSession()
    st = s.stub("iam")
    for _ in range(3):
        st.add_response("generate_credential_report", {"State": "INPROGRESS"}, {})
    result = run_collector(
        "iam_credential_report",
        lambda sess, r, a: iam_collectors.collect_credential_report(sess, r, a, max_attempts=3),
        s,
        REGION,
        ACCOUNT,
    )
    assert result.status == CollectorStatus.TIMEOUT


def test_credential_report_access_denied():
    s = StubSession()
    s.stub("iam").add_client_error("generate_credential_report", "AccessDenied", http_status_code=403)
    result = run_collector("iam_credential_report", iam_collectors.collect_credential_report, s, REGION, ACCOUNT)
    assert result.status == CollectorStatus.ACCESS_DENIED


def _enc(doc):
    return quote(json.dumps(doc))


ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def test_authorization_details_paginates_and_decodes_documents():
    s = StubSession()
    st = s.stub("iam")
    st.add_response(
        "get_account_authorization_details",
        {
            "UserDetailList": [
                {
                    "UserName": "alice",
                    "Arn": "arn:aws:iam::111122223333:user/alice",
                    "GroupList": ["admins"],
                    "AttachedManagedPolicies": [
                        {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
                    ],
                    "UserPolicyList": [{"PolicyName": "inl", "PolicyDocument": _enc(ADMIN)}],
                }
            ],
            "GroupDetailList": [
                {
                    "GroupName": "admins",
                    "Arn": "arn:aws:iam::111122223333:group/admins",
                    "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
                }
            ],
            "IsTruncated": True,
            "Marker": "m1",
        },
        {},
    )
    st.add_response(
        "get_account_authorization_details",
        {
            "RoleDetailList": [
                {
                    "RoleName": "app",
                    "Arn": "arn:aws:iam::111122223333:role/app",
                    "Path": "/",
                    "AssumeRolePolicyDocument": _enc(TRUST),
                    "RoleLastUsed": {},
                }
            ],
            "Policies": [
                {
                    "PolicyName": "custom",
                    "Arn": "arn:aws:iam::111122223333:policy/custom",
                    "AttachmentCount": 0,
                    "PolicyVersionList": [
                        {"Document": _enc({"Statement": []}), "VersionId": "v1", "IsDefaultVersion": False},
                        {"Document": _enc(ADMIN), "VersionId": "v2", "IsDefaultVersion": True},
                    ],
                },
                {
                    "PolicyName": "Unattached",
                    "Arn": "arn:aws:iam::aws:policy/Unattached",
                    "AttachmentCount": 0,
                    "PolicyVersionList": [],
                },
            ],
            "IsTruncated": False,
        },
        {"Marker": "m1"},
    )
    result = run_collector(
        "iam_authorization_details", iam_collectors.collect_authorization_details, s, REGION, ACCOUNT
    )
    assert result.ok, result.error_code
    d = result.items[0]
    assert d["users"][0]["inline"]["inl"] == ADMIN
    assert d["groups"]["admins"]["attached"] == ["arn:aws:iam::aws:policy/AdministratorAccess"]
    assert d["roles"][0]["trust"] == TRUST
    assert d["policies"]["arn:aws:iam::111122223333:policy/custom"]["document"] == ADMIN  # default version only
    assert "arn:aws:iam::aws:policy/Unattached" not in d["policies"]
    st.assert_no_pending_responses()


def test_password_policy_absent_is_ok_none():
    s = StubSession()
    s.stub("iam").add_client_error("get_account_password_policy", "NoSuchEntity", http_status_code=404)
    result = run_collector("iam_password_policy", iam_collectors.collect_password_policy, s, REGION, ACCOUNT)
    assert result.ok and result.items == [{"policy": None}]


def test_account_summary():
    s = StubSession()
    s.stub("iam").add_response(
        "get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0, "Users": 3}}, {}
    )
    result = run_collector("iam_account_summary", iam_collectors.collect_account_summary, s, REGION, ACCOUNT)
    assert result.items == [{"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}]
