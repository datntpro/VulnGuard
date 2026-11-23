"""
1.8: Test hồi quy phát hiện — chạy scanner THẬT trên repo mẫu có lỗi đã biết,
đảm bảo số lỗi tìm được không tụt về 0 (bắt lỗi "âm thầm bỏ qua tool" / regress).

Tool nào chưa cài thì skip (không fail) — nhưng nếu đã cài mà tìm 0 lỗi trên
fixture cố ý có lỗi thì FAIL.
"""
import asyncio
import os
import shutil

import pytest

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable")


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.mark.skipif(not shutil.which("bandit"), reason="bandit chưa cài")
def test_bandit_finds_known_issues():
    from scanner.scanners.sast import BanditScanner
    findings = _run(BanditScanner(FIXTURE).scan())
    assert len(findings) >= 2, f"Bandit phải tìm ≥2 lỗi trên fixture, chỉ thấy {len(findings)}"
    # có ít nhất 1 lỗi liên quan hardcoded secret / shell
    joined = " ".join((f.get("title", "") + f.get("description", "")) for f in findings).lower()
    assert ("password" in joined or "hardcoded" in joined or "shell" in joined or "subprocess" in joined)


def test_fixture_has_planted_bugs():
    # đảm bảo fixture tồn tại & còn chứa lỗi (không bị ai "dọn" mất)
    src = open(os.path.join(FIXTURE, "app.py")).read()
    assert "SuperSecretP@ssw0rd123" in src and "shell=True" in src


@pytest.mark.skipif(not shutil.which("bandit"), reason="bandit chưa cài")
def test_orchestrator_reports_ok_not_empty():
    """Orchestrator chạy SAST trên fixture → bandit status 'ok' với count > 0 (không 'skipped')."""
    from scanner.orchestrator import Orchestrator
    findings, logs = _run(Orchestrator(FIXTURE, ["SAST"]).run())
    assert "bandit" in logs
    assert logs["bandit"]["status"] == "ok" and logs["bandit"]["count"] > 0
