"""Thiết lập môi trường test (offline, sqlite tạm) + seed EPSS/KEV."""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="vgtest_")
os.makedirs(os.path.join(_TMP, "db"), exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/db/test.db")
os.environ.setdefault("AI_CONFIG_FILE", os.path.join(_TMP, "ai.json"))
os.environ.setdefault("AUTH_ENABLED", "true")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("VULNGUARD_SETUP_TOKEN", "test-setup-token")
os.environ.setdefault("DEPLOY_MODE", "native")

import pytest
from scanner.intel import feeds


@pytest.fixture(scope="session", autouse=True)
def _seed_intel():
    feeds.seed_for_test({"CVE-2021-44228": 0.97, "CVE-2020-0001": 0.02}, ["CVE-2021-44228"])


@pytest.fixture(autouse=True)
def _pentest_sandbox_default(monkeypatch):
    """D7: test không chạy trong docker thật → tắt trần autonomy native (test D7 tự bật lại)."""
    from scanner.pentest.settings import pentest_settings
    monkeypatch.setattr(pentest_settings, "require_sandbox", "false")
