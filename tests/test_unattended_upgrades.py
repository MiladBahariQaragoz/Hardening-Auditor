from __future__ import annotations

from auditor.checks.unattended_upgrades import check
from auditor.models import Status
from tests.fakes import FakeHost

CONF = "/etc/apt/apt.conf.d/20auto-upgrades"
ENABLED = (
    'APT::Periodic::Update-Package-Lists "1";\n'
    'APT::Periodic::Unattended-Upgrade "1";\n'
)


def test_pass_when_both_directives_enabled():
    assert check(FakeHost(files={CONF: ENABLED})).status is Status.PASS


def test_fail_when_upgrade_disabled():
    conf = (
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "0";\n'
    )
    r = check(FakeHost(files={CONF: conf}))
    assert r.status is Status.FAIL
    assert "upgrade=0" in r.found


def test_fail_when_file_missing():
    r = check(FakeHost())
    assert r.status is Status.FAIL
    assert "missing" in r.found
