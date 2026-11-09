from pathlib import Path

from vmssh.core.models import InitReport, StepResult, VMConfig


def make_report(*steps):
    report = InitReport(VMConfig("192.0.2.10", "testuser", "lab", 22, Path("key")))
    report.steps.extend(StepResult(name, status) for name, status in steps)
    return report


def test_report_success_allows_explicitly_skipped_optional_features():
    report = make_report(
        ("key_validation", "success"),
        ("ssh_password_connection", "success"),
        ("public_key_deployment", "skipped"),
        ("ssh_config", "skipped"),
        ("public_key_authentication", "skipped"),
        ("sudo_nopasswd", "skipped"),
    )
    assert report.success is True


def test_report_fails_if_an_enabled_operation_failed():
    report = make_report(
        ("key_validation", "success"),
        ("ssh_password_connection", "success"),
        ("public_key_deployment", "success"),
        ("ssh_config", "success"),
        ("public_key_authentication", "failed"),
    )
    assert report.success is False
