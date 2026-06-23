from __future__ import annotations

from auditor.checks.sysctl_network import PARAMETERS, check
from auditor.models import Status
from tests.fakes import FakeHost


def _all(values: dict[str, str]) -> dict[str, str]:
    """Build a /proc/sys file map from {path: value}."""
    return {path: f"{values[path]}\n" for path in values}


def _hardened() -> dict[str, str]:
    return {path: want for _cid, path, want in PARAMETERS}


def test_pass_when_all_parameters_hardened():
    assert check(FakeHost(files=_all(_hardened()))).status is Status.PASS


def test_fail_when_one_parameter_wrong():
    vals = _hardened()
    vals["/proc/sys/net/ipv4/ip_forward"] = "1"  # routing enabled = bad
    r = check(FakeHost(files=_all(vals)))
    assert r.status is Status.FAIL
    assert "ip_forward" in r.found
    assert "1 of" in r.found


def test_skip_when_proc_sys_unreadable():
    assert check(FakeHost()).status is Status.SKIP


def test_unreadable_parameters_are_not_penalised():
    # Only one parameter present and it's correct -> pass on what we can read.
    one = {"/proc/sys/net/ipv4/tcp_syncookies": "1\n"}
    assert check(FakeHost(files=one)).status is Status.PASS
